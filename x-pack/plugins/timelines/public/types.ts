/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ReactElement } from 'react';
import type { SensorAPI } from 'react-beautiful-dnd';
import { Store } from 'redux';
import { CoreStart } from '@kbn/core/public';
import type { DataPublicPluginStart } from '@kbn/data-plugin/public';
import { CasesUiStart } from '@kbn/cases-plugin/public';
import type { TriggersAndActionsUIPublicPluginStart as TriggersActionsStart } from '@kbn/triggers-actions-ui-plugin/public';
import { ApmBase } from '@elastic/apm-rum';
import type {
  LoadingPanelProps,
  UseDraggableKeyboardWrapper,
  UseDraggableKeyboardWrapperProps,
} from './components';
export type { SortDirection } from '../common/types';
import type { UseAddToTimelineProps, UseAddToTimeline } from './hooks/use_add_to_timeline';
import { HoverActionsConfig } from './components/hover_actions';
export interface TimelinesUIStart {
  getHoverActions: () => HoverActionsConfig;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getTimelineReducer: () => any;
  getLoadingPanel: (props: LoadingPanelProps) => ReactElement<LoadingPanelProps>;
  getUseAddToTimeline: () => (props: UseAddToTimelineProps) => UseAddToTimeline;
  getUseAddToTimelineSensor: () => (api: SensorAPI) => void;
  getUseDraggableKeyboardWrapper: () => (
    props: UseDraggableKeyboardWrapperProps
  ) => UseDraggableKeyboardWrapper;
  setTimelineEmbeddedStore: (store: Store) => void;
}

export interface TimelinesStartPlugins {
  data: DataPublicPluginStart;
  cases: CasesUiStart;
  triggersActionsUi: TriggersActionsStart;
  apm?: ApmBase;
}

export type TimelinesStartServices = CoreStart & TimelinesStartPlugins;
