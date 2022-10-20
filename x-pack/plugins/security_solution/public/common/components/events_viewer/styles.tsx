/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { EuiFlexGroup, EuiFlexItem, EuiPanel } from '@elastic/eui';
import styled from 'styled-components';
import type { ViewSelection } from '../event_rendered_view/selector';
export const SELECTOR_TIMELINE_GLOBAL_CONTAINER = 'securitySolutionTimeline__container';
export const EVENTS_TABLE_CLASS_NAME = 'siemEventsTable';

export const FullWidthFlexGroup = styled(EuiFlexGroup)<{ $visible?: boolean }>`
  overflow: hidden;
  margin: 0;
  min-height: 490px;
  display: ${({ $visible = true }) => ($visible ? 'flex' : 'none')};
`;

export const UpdatedFlexGroup = styled(EuiFlexGroup)<{ $view?: ViewSelection }>`
  ${({ $view, theme }) => ($view === 'gridView' ? `margin-right: ${theme.eui.euiSizeXL};` : '')}
  position: absolute;
  z-index: ${({ theme }) => theme.eui.euiZLevel1 - 3};
  right: 0px;
`;

export const UpdatedFlexItem = styled(EuiFlexItem)<{ $show: boolean }>`
  ${({ $show }) => ($show ? '' : 'visibility: hidden;')}
`;

export const AlertCount = styled.span`
  font-size: ${({ theme }) => theme.eui.euiFontSizeXS};
  font-weight: ${({ theme }) => theme.eui.euiFontWeightSemiBold};
  border-right: ${({ theme }) => theme.eui.euiBorderThin};
  margin-right: ${({ theme }) => theme.eui.euiSizeS};
  padding-right: ${({ theme }) => theme.eui.euiSizeM};
`;

export const EventsContainerLoading = styled.div.attrs(({ className = '' }) => ({
  className: `${SELECTOR_TIMELINE_GLOBAL_CONTAINER} ${className}`,
}))`
  position: relative;
  width: 100%;
  overflow: hidden;
  flex: 1;
  display: flex;
  flex-direction: column;
`;

export const StyledEuiPanel = styled(EuiPanel)<{ $isFullScreen: boolean }>`
  display: flex;
  flex-direction: column;
  position: relative;
  width: 100%;

  ${({ $isFullScreen }) =>
    $isFullScreen &&
    `
    border: 0;
    box-shadow: none;
    padding-top: 0;
    padding-bottom: 0;
`}
`;
