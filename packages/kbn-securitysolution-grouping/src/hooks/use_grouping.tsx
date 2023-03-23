/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

import { FieldSpec } from '@kbn/data-views-plugin/common';
import React, { useCallback, useMemo, useReducer } from 'react';
import { UiCounterMetricType } from '@kbn/analytics';
import { groupsReducerWithStorage, initialState } from './state/reducer';
import { GroupingProps, GroupSelectorProps, isNoneGroup } from '..';
import { useGroupingPagination } from './use_grouping_pagination';
import { groupActions, groupByIdSelector } from './state';
import { useGetGroupSelector } from './use_get_group_selector';
import { defaultGroup, GroupOption, GroupsPagingSettingsById } from './types';
import { Grouping as GroupingComponent } from '../components/grouping';

/** Interface for grouping object where T is the `GroupingAggregation`
 *  @interface GroupingArgs<T>
 */
interface Grouping<T> {
  getGrouping: (props: DynamicGroupingProps<T>) => React.ReactElement;
  groupSelector: React.ReactElement<GroupSelectorProps>;
  pagination: {
    pagingSettings: GroupsPagingSettingsById;
    reset: () => void;
  };
  selectedGroups: string[];
}

/** Type for static grouping component props where T is the `GroupingAggregation`
 *  @interface StaticGroupingProps<T>
 */
type StaticGroupingProps<T> = Pick<
  GroupingProps<T>,
  | 'groupPanelRenderer'
  | 'groupStatsRenderer'
  | 'inspectButton'
  | 'onGroupToggle'
  | 'renderChildComponent'
  | 'unit'
>;

/** Type for dynamic grouping component props where T is the `GroupingAggregation`
 *  @interface DynamicGroupingProps<T>
 */
type DynamicGroupingProps<T> = Pick<GroupingProps<T>, 'data' | 'isLoading' | 'takeActionItems'>;

/** Interface for configuring grouping package where T is the `GroupingAggregation`
 *  @interface GroupingArgs<T>
 */
interface GroupingArgs<T> {
  componentProps: StaticGroupingProps<T>;
  defaultGroupingOptions: GroupOption[];
  fields: FieldSpec[];
  groupingId: string;
  maxGroupingLevels?: number;
  /** for tracking
   * @param param { groupByField: string; tableId: string } selected group and table id
   */
  onGroupChange?: (param: { groupByField: string; tableId: string }) => void;
  tracker?: (
    type: UiCounterMetricType,
    event: string | string[],
    count?: number | undefined
  ) => void;
}

/**
 * Hook to configure grouping component
 * @param componentProps {@link StaticGroupingProps} props passed to the grouping component.
 * These props are static compared to the dynamic props passed later to getGrouping
 * @param defaultGroupingOptions defines the grouping options as an array of {@link GroupOption}
 * @param fields FieldSpec array serialized version of DataViewField fields. Available in the custom grouping options
 * @param groupingId Unique identifier of the grouping component. Used in local storage
 * @param maxGroupingLevels maximum group nesting levels (optional)
 * @param onGroupChange callback executed when selected group is changed, used for tracking
 * @param tracker telemetry handler
 * @returns {@link Grouping} the grouping constructor { getGrouping, groupSelector, pagination, selectedGroups }
 */
export const useGrouping = <T,>({
  componentProps,
  defaultGroupingOptions,
  fields,
  groupingId,
  maxGroupingLevels,
  onGroupChange,
  tracker,
}: GroupingArgs<T>): Grouping<T> => {
  const [groupingState, dispatch] = useReducer(groupsReducerWithStorage, initialState);
  const { activeGroups: selectedGroups } = useMemo(
    () => groupByIdSelector({ groups: groupingState }, groupingId) ?? defaultGroup,
    [groupingId, groupingState]
  );

  const groupSelector = useGetGroupSelector({
    defaultGroupingOptions,
    dispatch,
    fields,
    groupingId,
    groupingState,
    maxGroupingLevels,
    onGroupChange,
    tracker,
  });

  const pagination = useGroupingPagination({ groupingId, groupingState, dispatch });

  const getGrouping = useCallback(
    /**
     *
     * @param props {@link DynamicGroupingProps}
     */
    (props: DynamicGroupingProps<T>): React.ReactElement =>
      isNoneGroup(selectedGroups) ? (
        componentProps.renderChildComponent([])
      ) : (
        <GroupingComponent
          {...componentProps}
          {...props}
          groupingId={groupingId}
          groupSelector={groupSelector}
          pagination={pagination}
          selectedGroups={selectedGroups}
          tracker={tracker}
        />
      ),
    [componentProps, groupSelector, groupingId, pagination, selectedGroups, tracker]
  );

  const resetPagination = useCallback(() => {
    selectedGroups.forEach((selectedGroups, i, arr) => {
      dispatch(
        groupActions.updateGroupActivePage({ id: groupingId, activePage: 0, selectedGroups })
      );
    });
  }, [groupingId, selectedGroups]);

  return useMemo(
    () => ({
      getGrouping,
      groupSelector,
      selectedGroups,
      pagination: {
        pagingSettings: pagination.pagingSettings,
        reset: resetPagination,
      },
    }),
    [getGrouping, groupSelector, pagination.pagingSettings, resetPagination, selectedGroups]
  );
};
