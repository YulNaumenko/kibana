/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import React from 'react';
import { render } from '@testing-library/react';
import { buildMockDashboardApi } from '../mocks';
import { InternalDashboardTopNav } from './internal_dashboard_top_nav';
import { setMockedPresentationUtilServices } from '@kbn/presentation-util-plugin/public/mocks';
import { TopNavMenuProps } from '@kbn/navigation-plugin/public';
import { DashboardContext } from '../dashboard_api/use_dashboard_api';
import { dataService, navigationService } from '../services/kibana_services';

jest.mock('../dashboard_app/top_nav/dashboard_editing_toolbar', () => ({
  DashboardEditingToolbar: () => {
    return <div>mockDashboardEditingToolbar</div>;
  },
}));
describe('Internal dashboard top nav', () => {
  const mockTopNav = (badges: TopNavMenuProps['badges'] | undefined[]) => {
    if (badges) {
      return badges?.map((badge, index) => (
        <div key={index} className="badge">
          {badge?.badgeText}
        </div>
      ));
    } else {
      return <></>;
    }
  };

  beforeEach(() => {
    setMockedPresentationUtilServices();
    dataService.query.filterManager.getFilters = jest.fn().mockReturnValue([]);
    // topNavMenu is mocked as a jest.fn() so we want to mock it with a component
    // @ts-ignore type issue with the mockTopNav for this test suite
    navigationService.ui.TopNavMenu = ({ badges }: TopNavMenuProps) => mockTopNav(badges);
  });

  it('should not render the managed badge by default', async () => {
    const component = render(
      <DashboardContext.Provider value={buildMockDashboardApi().api}>
        <InternalDashboardTopNav redirectTo={jest.fn()} />
      </DashboardContext.Provider>
    );

    expect(component.queryByText('Managed')).toBeNull();
  });

  it('should render the managed badge when the dashboard is managed', async () => {
    const { api } = buildMockDashboardApi();
    const dashboardApi = {
      ...api,
      isManaged: true,
    };
    const component = render(
      <DashboardContext.Provider value={dashboardApi}>
        <InternalDashboardTopNav redirectTo={jest.fn()} />
      </DashboardContext.Provider>
    );

    expect(component.getByText('Managed')).toBeInTheDocument();
  });
});
