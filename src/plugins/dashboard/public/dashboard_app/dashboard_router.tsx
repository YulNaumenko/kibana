/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import './_dashboard_app.scss';

import React from 'react';
import { parse, ParsedQuery } from 'query-string';
import { render, unmountComponentAtNode } from 'react-dom';
import { HashRouter, RouteComponentProps, Redirect } from 'react-router-dom';
import { Routes, Route } from '@kbn/shared-ux-router';
import { ViewMode } from '@kbn/embeddable-plugin/public';
import { AppMountParameters, CoreStart } from '@kbn/core/public';
import { KibanaRenderContextProvider } from '@kbn/react-kibana-context-render';
import { createKbnUrlStateStorage, withNotifyOnErrors } from '@kbn/kibana-utils-plugin/public';

import {
  createDashboardListingFilterUrl,
  CREATE_NEW_DASHBOARD_URL,
  DASHBOARD_APP_ID,
  LANDING_PAGE_PATH,
  VIEW_DASHBOARD_URL,
} from '../dashboard_constants';
import { DashboardApp } from './dashboard_app';
import { pluginServices } from '../services/plugin_services';
import { RedirectToProps } from '../dashboard_container/types';
import { createDashboardEditUrl } from '../dashboard_constants';
import { DashboardNoMatch } from './listing_page/dashboard_no_match';
import { DashboardMountContext } from './hooks/dashboard_mount_context';
import { DashboardEmbedSettings, DashboardMountContextProps } from './types';
import { DashboardListingPage } from './listing_page/dashboard_listing_page';
import { dashboardReadonlyBadge, getDashboardPageTitle } from './_dashboard_app_strings';

export const dashboardUrlParams = {
  showTopMenu: 'show-top-menu',
  showQueryInput: 'show-query-input',
  showTimeFilter: 'show-time-filter',
  hideFilterBar: 'hide-filter-bar',
};

export interface DashboardMountProps {
  appUnMounted: () => void;
  element: AppMountParameters['element'];
  coreStart: CoreStart;
  mountContext: DashboardMountContextProps;
}

export async function mountApp({
  coreStart,
  element,
  appUnMounted,
  mountContext,
}: DashboardMountProps) {
  const {
    chrome: { setBadge, docTitle, setHelpExtension },
    dashboardCapabilities: { showWriteControls },
    documentationLinks: { dashboardDocLink },
    application: { navigateToApp },
    settings: { uiSettings },
    data: dataStart,
    notifications,
    embeddable,
  } = pluginServices.getServices();

  let globalEmbedSettings: DashboardEmbedSettings | undefined;

  const getUrlStateStorage = (history: RouteComponentProps['history']) =>
    createKbnUrlStateStorage({
      history,
      useHash: uiSettings.get('state:storeInSessionStorage'),
      ...withNotifyOnErrors(notifications.toasts),
    });

  const redirect = (redirectTo: RedirectToProps) => {
    let path;
    let state;
    if (redirectTo.destination === 'dashboard') {
      path = redirectTo.id ? createDashboardEditUrl(redirectTo.id) : CREATE_NEW_DASHBOARD_URL;
      if (redirectTo.editMode) {
        state = { viewMode: ViewMode.EDIT };
      }
    } else {
      path = createDashboardListingFilterUrl(redirectTo.filter);
    }
    navigateToApp(DASHBOARD_APP_ID, { path: `#/${path}`, state, replace: redirectTo.useReplace });
  };

  const getDashboardEmbedSettings = (
    routeParams: ParsedQuery<string>
  ): DashboardEmbedSettings | undefined => {
    return {
      forceShowTopNavMenu: routeParams[dashboardUrlParams.showTopMenu] === 'true',
      forceShowQueryInput: routeParams[dashboardUrlParams.showQueryInput] === 'true',
      forceShowDatePicker: routeParams[dashboardUrlParams.showTimeFilter] === 'true',
      forceHideFilterBar: routeParams[dashboardUrlParams.hideFilterBar] === 'true',
    };
  };

  const renderDashboard = (routeProps: RouteComponentProps<{ id?: string }>) => {
    const routeParams = parse(routeProps.history.location.search);
    if (routeParams.embed === 'true' && !globalEmbedSettings) {
      globalEmbedSettings = getDashboardEmbedSettings(routeParams);
    }
    return (
      <DashboardApp
        history={routeProps.history}
        embedSettings={globalEmbedSettings}
        savedDashboardId={routeProps.match.params.id}
        redirectTo={redirect}
      />
    );
  };

  const renderListingPage = (routeProps: RouteComponentProps) => {
    docTitle.change(getDashboardPageTitle());
    const routeParams = parse(routeProps.history.location.search);
    const title = (routeParams.title as string) || undefined;
    const filter = (routeParams.filter as string) || undefined;
    return (
      <DashboardListingPage
        initialFilter={filter}
        title={title}
        kbnUrlStateStorage={getUrlStateStorage(routeProps.history)}
        redirectTo={redirect}
      />
    );
  };

  const renderNoMatch = (routeProps: RouteComponentProps) => {
    return <DashboardNoMatch history={routeProps.history} />;
  };

  const hasEmbeddableIncoming = Boolean(
    embeddable.getStateTransfer().getIncomingEmbeddablePackage(DASHBOARD_APP_ID, false)
  );
  if (!hasEmbeddableIncoming) {
    dataStart.dataViews.clearCache();
  }

  // dispatch synthetic hash change event to update hash history objects
  // this is necessary because hash updates triggered by using popState won't trigger this event naturally.
  const unlistenParentHistory = mountContext.scopedHistory().listen(() => {
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  });

  const app = (
    <KibanaRenderContextProvider {...coreStart}>
      <DashboardMountContext.Provider value={mountContext}>
        <HashRouter>
          <Routes>
            <Route
              path={[CREATE_NEW_DASHBOARD_URL, `${VIEW_DASHBOARD_URL}/:id`]}
              render={renderDashboard}
            />
            <Route exact path={LANDING_PAGE_PATH} render={renderListingPage} />
            <Route exact path="/">
              <Redirect to={LANDING_PAGE_PATH} />
            </Route>
            <Route render={renderNoMatch} />
          </Routes>
        </HashRouter>
      </DashboardMountContext.Provider>
    </KibanaRenderContextProvider>
  );

  setHelpExtension({
    appName: getDashboardPageTitle(),
    links: [
      {
        linkType: 'documentation',
        href: `${dashboardDocLink}`,
      },
    ],
  });

  if (!showWriteControls) {
    setBadge({
      text: dashboardReadonlyBadge.getText(),
      tooltip: dashboardReadonlyBadge.getTooltip(),
      iconType: 'glasses',
    });
  }
  render(app, element);
  return () => {
    dataStart.search.session.clear();
    unlistenParentHistory();
    unmountComponentAtNode(element);
    appUnMounted();
  };
}
