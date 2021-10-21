/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ElasticsearchClient } from 'kibana/server';
import { AlertHistoryEsIndexConnectorId } from '../../common';
import { ActionResult, PreConfiguredAction } from '../types';

export async function getTotalCount(
  esClient: ElasticsearchClient,
  kibanaIndex: string,
  preconfiguredActions?: PreConfiguredAction[]
) {
  const scriptedMetric = {
    scripted_metric: {
      init_script: 'state.types = [:]',
      map_script: `
        String actionType = doc['action.actionTypeId'].value;
        state.types.put(actionType, state.types.containsKey(actionType) ? state.types.get(actionType) + 1 : 1);
      `,
      // Combine script is executed per cluster, but we already have a key-value pair per cluster.
      // Despite docs that say this is optional, this script can't be blank.
      combine_script: 'return state',
      // Reduce script is executed across all clusters, so we need to add up all the total from each cluster
      // This also needs to account for having no data
      reduce_script: `
        Map result = [:];
        for (Map m : states.toArray()) {
          if (m !== null) {
            for (String k : m.keySet()) {
              result.put(k, result.containsKey(k) ? result.get(k) + m.get(k) : m.get(k));
            }
          }
        }
        return result;
      `,
    },
  };

  const { body: searchResult } = await esClient.search({
    index: kibanaIndex,
    size: 0,
    body: {
      query: {
        bool: {
          filter: [{ term: { type: 'action' } }],
        },
      },
      aggs: {
        byActionTypeId: scriptedMetric,
      },
    },
  });
  // @ts-expect-error aggegation type is not specified
  const aggs = searchResult.aggregations?.byActionTypeId.value?.types;
  const countByType = Object.keys(aggs).reduce(
    // ES DSL aggregations are returned as `any` by esClient.search
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (obj: any, key: string) => ({
      ...obj,
      [replaceFirstAndLastDotSymbols(key)]: aggs[key],
    }),
    {}
  );
  if (preconfiguredActions && preconfiguredActions.length) {
    for (const preconfiguredAction of preconfiguredActions) {
      const actionTypeId = replaceFirstAndLastDotSymbols(preconfiguredAction.actionTypeId);
      countByType[actionTypeId] = countByType[actionTypeId] || 0;
      countByType[actionTypeId]++;
    }
  }
  return {
    countTotal:
      Object.keys(aggs).reduce((total: number, key: string) => parseInt(aggs[key], 10) + total, 0) +
      (preconfiguredActions?.length ?? 0),
    countByType,
  };
}

export async function getInUseTotalCount(
  esClient: ElasticsearchClient,
  kibanaIndex: string
): Promise<{
  countTotal: number;
  countByType: Record<string, number>;
  countByAlertHistoryConnectorType: number;
}> {
  const scriptedMetric = {
    scripted_metric: {
      init_script: 'state.connectorIds = new HashMap(); state.total = 0;',
      map_script: `
        String connectorId = doc['references.id'].value;
        String actionRef = doc['references.name'].value;
        if (state.connectorIds[connectorId] === null) {
          state.connectorIds[connectorId] = actionRef;
          state.total++;
        }
      `,
      // Combine script is executed per cluster, but we already have a key-value pair per cluster.
      // Despite docs that say this is optional, this script can't be blank.
      combine_script: 'return state',
      // Reduce script is executed across all clusters, so we need to add up all the total from each cluster
      // This also needs to account for having no data
      reduce_script: `
          Map connectorIds = [:];
          long total = 0;
          for (state in states) {
            if (state !== null) {
              total += state.total;
              for (String k : state.connectorIds.keySet()) {
                connectorIds.put(k, connectorIds.containsKey(k) ? connectorIds.get(k) + state.connectorIds.get(k) : state.connectorIds.get(k));
              }
            }
          }
          Map result = new HashMap();
          result.total = total;
          result.connectorIds = connectorIds;
          return result;
      `,
    },
  };

  const preconfiguredActionsScriptedMetric = {
    scripted_metric: {
      init_script: 'state.actionRefs = new HashMap(); state.total = 0;',
      map_script: `
        String actionRef = doc['alert.actions.actionRef'].value;
        String actionTypeId = doc['alert.actions.actionTypeId'].value;
        if (actionRef.startsWith('preconfigured:') && state.actionRefs[actionRef] === null) {
          HashMap map = new HashMap();
          map.actionRef = actionRef;
          map.actionTypeId = actionTypeId;
          state.actionRefs[actionRef] = map;
          state.total++;
        }
      `,
      // Combine script is executed per cluster, but we already have a key-value pair per cluster.
      // Despite docs that say this is optional, this script can't be blank.
      combine_script: 'return state',
      // Reduce script is executed across all clusters, so we need to add up all the total from each cluster
      // This also needs to account for having no data
      reduce_script: `
          Map actionRefs = [:];
          long total = 0;
          for (state in states) {
            if (state !== null) {
              total += state.total;
              for (String k : state.actionRefs.keySet()) {
                actionRefs.put(k, state.actionRefs.get(k));
              }
            }
          }
          Map result = new HashMap();
          result.total = total;
          result.actionRefs = actionRefs;
          return result;
      `,
    },
  };

  const { body: actionResults } = await esClient.search({
    index: kibanaIndex,
    size: 0,
    body: {
      query: {
        bool: {
          filter: {
            bool: {
              must_not: {
                term: {
                  type: 'action_task_params',
                },
              },
              must: {
                bool: {
                  should: [
                    {
                      nested: {
                        path: 'references',
                        query: {
                          bool: {
                            filter: {
                              bool: {
                                must: [
                                  {
                                    term: {
                                      'references.type': 'action',
                                    },
                                  },
                                ],
                              },
                            },
                          },
                        },
                      },
                    },
                    {
                      nested: {
                        path: 'alert.actions',
                        query: {
                          bool: {
                            filter: {
                              bool: {
                                must: [
                                  {
                                    prefix: {
                                      'alert.actions.actionRef': {
                                        value: 'preconfigured:',
                                      },
                                    },
                                  },
                                ],
                              },
                            },
                          },
                        },
                      },
                    },
                  ],
                },
              },
            },
          },
        },
      },
      aggs: {
        refs: {
          nested: {
            path: 'references',
          },
          aggs: {
            actionRefIds: scriptedMetric,
          },
        },
        preconfigured_actions: {
          nested: {
            path: 'alert.actions',
          },
          aggs: {
            preconfiguredActionRefIds: preconfiguredActionsScriptedMetric,
          },
        },
      },
    },
  });

  // @ts-expect-error aggegation type is not specified
  const aggs = actionResults.aggregations.refs.actionRefIds.value;
  const preconfiguredActionsAggs =
    // @ts-expect-error aggegation type is not specified
    actionResults.aggregations.preconfigured_actions?.preconfiguredActionRefIds.value;
  const {
    body: { hits: actions },
  } = await esClient.search<{
    action: ActionResult;
  }>({
    index: kibanaIndex,
    _source_includes: ['action'],
    body: {
      query: {
        bool: {
          must: [
            {
              term: { type: 'action' },
            },
            {
              terms: {
                _id: Object.entries(aggs.connectorIds).map(([key]) => `action:${key}`),
              },
            },
          ],
        },
      },
    },
  });
  const countByActionTypeId = actions.hits.reduce(
    (actionTypeCount: Record<string, number>, action) => {
      const actionSource = action._source!;
      const alertTypeId = replaceFirstAndLastDotSymbols(actionSource.action.actionTypeId);
      const currentCount =
        actionTypeCount[alertTypeId] !== undefined ? actionTypeCount[alertTypeId] : 0;
      actionTypeCount[alertTypeId] = currentCount + 1;
      return actionTypeCount;
    },
    {}
  );

  let preconfiguredAlertHistoryConnectors = 0;
  const preconfiguredActionsRefs: Array<{
    actionTypeId: string;
    actionRef: string;
  }> = preconfiguredActionsAggs ? Object.values(preconfiguredActionsAggs?.actionRefs) : [];
  for (const { actionRef, actionTypeId: rawActionTypeId } of preconfiguredActionsRefs) {
    const actionTypeId = replaceFirstAndLastDotSymbols(rawActionTypeId);
    countByActionTypeId[actionTypeId] = countByActionTypeId[actionTypeId] || 0;
    countByActionTypeId[actionTypeId]++;
    if (actionRef === `preconfigured:${AlertHistoryEsIndexConnectorId}`) {
      preconfiguredAlertHistoryConnectors++;
    }
  }

  return {
    countTotal: aggs.total + (preconfiguredActionsAggs?.total ?? 0),
    countByType: countByActionTypeId,
    countByAlertHistoryConnectorType: preconfiguredAlertHistoryConnectors,
  };
}

function replaceFirstAndLastDotSymbols(strToReplace: string) {
  const hasFirstSymbolDot = strToReplace.startsWith('.');
  const appliedString = hasFirstSymbolDot ? strToReplace.replace('.', '__') : strToReplace;
  const hasLastSymbolDot = strToReplace.endsWith('.');
  return hasLastSymbolDot ? `${appliedString.slice(0, -1)}__` : appliedString;
}

export async function getExecutionsTotalCount(
  esClient: ElasticsearchClient,
  eventLogIndex: string
): Promise<{
  countTotal: number;
  countByType: Record<string, number>;
  countFailed: number;
  countFailedByType: Record<string, number>;
  avgExecutionTime: number;
  avgExecutionTimeByType: Record<string, number>;
}> {
  const scriptedMetric = {
    scripted_metric: {
      init_script: 'state.connectorTypes = [:];  state.total = 0;',
      map_script: `
        if (doc['kibana.saved_objects.type'].value == 'action') { 
          String connectorType = doc['kibana.saved_objects.type_id'].value; 
          state.connectorTypes.put(connectorType, state.connectorTypes.containsKey(connectorType) ? state.connectorTypes.get(connectorType) + 1 : 1);
          state.total++;
        }
      `,
      // Combine script is executed per cluster, but we already have a key-value pair per cluster.
      // Despite docs that say this is optional, this script can't be blank.
      combine_script: 'return state',
      // Reduce script is executed across all clusters, so we need to add up all the total from each cluster
      // This also needs to account for having no data
      reduce_script: `
          Map connectorTypes = [:];
          long total = 0;
          for (state in states) {
            if (state !== null) {
              total += state.total;
              for (String k : state.connectorTypes.keySet()) {
                connectorTypes.put(k, connectorTypes.containsKey(k) ? connectorTypes.get(k) + state.connectorTypes.get(k) : state.connectorTypes.get(k));
              }
            }
          }
          Map result = new HashMap();
          result.total = total;
          result.connectorTypes = connectorTypes;
          return result;
      `,
    },
  };

  const { body: actionResults } = await esClient.search({
    index: eventLogIndex,
    size: 0,
    body: {
      query: {
        bool: {
          filter: {
            bool: {
              must: [
                {
                  term: { 'event.action': 'execute' },
                },
                {
                  nested: {
                    path: 'kibana.saved_objects',
                    query: {
                      bool: {
                        must: [
                          {
                            term: {
                              'kibana.saved_objects.type': {
                                value: 'action',
                              },
                            },
                          },
                        ],
                      },
                    },
                  },
                },
              ],
            },
          },
        },
      },
      aggs: {
        totalExecutions: {
          nested: {
            path: 'kibana.saved_objects',
          },
          aggs: {
            byConnectorTypeId: scriptedMetric,
          },
        },
        failedExecutions: {
          filter: {
            bool: {
              filter: [
                {
                  term: {
                    'event.outcome': 'failure',
                  },
                },
              ],
            },
          },
          aggs: {
            refs: {
              nested: {
                path: 'kibana.saved_objects',
              },
              aggs: {
                byConnectorTypeId: scriptedMetric,
              },
            },
          },
        },
        avgDuration: { avg: { field: 'event.duration' } },
      },
    },
  });

  // @ts-expect-error aggegation type is not specified
  const aggsExecutions = actionResults.aggregations.totalExecutions?.byConnectorTypeId.value;
  const aggsAvgExecutionTime = Math.round(
    // @ts-expect-error aggegation type is not specified
    actionResults.aggregations.avgDuration.value / (1000 * 1000)
  ); // nano seconds
  const aggsFailedExecutions =
    // @ts-expect-error aggegation type is not specified
    actionResults.aggregations.failedExecutions?.refs?.byConnectorTypeId.value;

  const avgExecutionTimeByType: Record<string, number> = {};
  Promise.all(
    Object.entries(aggsExecutions.connectorTypes).map(([key]) =>
      esClient.search({
        index: eventLogIndex,
        size: 1,
        body: {
          query: {
            bool: {
              filter: {
                bool: {
                  must: [
                    {
                      term: { 'event.action': 'execute' },
                    },
                    {
                      nested: {
                        path: 'kibana.saved_objects',
                        query: {
                          bool: {
                            must: [
                              {
                                term: {
                                  'kibana.saved_objects.type': {
                                    value: 'action',
                                  },
                                },
                              },
                              {
                                term: {
                                  'kibana.saved_objects.type_id': {
                                    value: key,
                                  },
                                },
                              },
                            ],
                          },
                        },
                      },
                    },
                  ],
                },
              },
            },
          },
          aggs: {
            avgDuration: { avg: { field: 'event.duration' } },
          },
        },
      })
    )
  ).then((connectorTypeResults) => {
    avgExecutionTimeByType[replaceFirstAndLastDotSymbols('')] =
      // @ts-expect-error aggegation type is not specified
      Math.round(connectorTypeResults.aggregations?.avgDuration.value / (1000 * 1000));
  });

  return {
    countTotal: aggsExecutions.total,
    countByType: aggsExecutions.connectorTypes,
    countFailed: aggsFailedExecutions.total,
    countFailedByType: aggsFailedExecutions.connectorTypes,
    avgExecutionTime: aggsAvgExecutionTime,
    avgExecutionTimeByType,
  };
}
