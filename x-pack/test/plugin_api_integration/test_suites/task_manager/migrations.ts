/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import expect from '@kbn/expect';
import type { ApiResponse, estypes } from '@elastic/elasticsearch';
import { TaskInstanceWithDeprecatedFields } from '../../../../plugins/task_manager/server/task';
import { FtrProviderContext } from '../../../common/ftr_provider_context';

export default function createGetTests({ getService }: FtrProviderContext) {
  const es = getService('es');
  const esArchiver = getService('esArchiver');

  describe('migrations', () => {
    before(async () => {
      await esArchiver.load('x-pack/test/functional/es_archives/task_manager_tasks');
    });

    after(async () => {
      await esArchiver.unload('x-pack/test/functional/es_archives/task_manager_tasks');
    });

    it('8.0.0 migrates actions tasks with legacy id to saved object ids', async () => {
      // NOTE: We hae to use elastic search directly against the ".kibana" index because alerts do not expose the references which we want to test exists
      const response = await es.get<{ task: TaskInstanceWithDeprecatedFields }>({
        index: '.kibana_task_manager',
        id: 'task:be7e1250-3322-11eb-94c1-db6995e84f6a',
      });
      expect(response.statusCode).to.eql(200);
      expect(response.body._source?.task.params).to.eql(
        '{"spaceId":"user1","alertId":"4c0ff612-006a-590e-8bb5-ac42cf0a2878"}'
      );
    });

    it('8.0.0 migrates actions tasks from legacy id to saved object ids', async () => {
      const searchResult: ApiResponse<
        estypes.SearchResponse<{ task: TaskInstanceWithDeprecatedFields }>
      > = await es.search({
        index: '.kibana_task_manager',
        body: {
          query: {
            term: {
              _id: 'task:be7e1250-3322-11eb-94c1-db6995e8389f',
            },
          },
        },
      });
      expect(searchResult.statusCode).to.equal(200);
      expect((searchResult.body.hits.total as estypes.SearchTotalHits).value).to.equal(1);
      const hit = searchResult.body.hits.hits[0];
      expect(hit!._source!.task.params!).to.equal(
        '{"spaceId":"user1","actionTaskParamsId":"c2d08bdf-ff59-51c1-a11a-d29a2140650a"}'
      );
    });
  });
}
