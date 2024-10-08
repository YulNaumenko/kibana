/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import React from 'react';
import { sortBy } from 'lodash';

import { EuiIcon, EuiSideNavItemType, EuiFlexGroup, EuiFlexItem, EuiIconTip } from '@elastic/eui';
import { AppMountParameters } from '@kbn/core/public';
import { reactRouterNavigate } from '@kbn/kibana-react-plugin/public';
import { ManagementApp, ManagementSection } from '../../utils';

import { ManagementItem } from '../../utils/management_item';

interface ManagementSidebarNavProps {
  sections: ManagementSection[];
  history: AppMountParameters['history'];
  selectedId: string;
}

/** @internal **/
export const managementSidebarNav = ({
  selectedId,
  sections,
  history,
}: ManagementSidebarNavProps) => {
  const sectionsToNavItems = (managementSections: ManagementSection[]) => {
    const sortedManagementSections = sortBy(managementSections, 'order');

    return sortedManagementSections.reduce<Array<EuiSideNavItemType<any>>>((acc, section) => {
      const apps = sortBy(
        section.getAppsEnabled().filter((app) => !app.hideFromSidebar),
        'order'
      );

      if (apps.length) {
        if (!section.hideFromSidebar) {
          acc.push({
            ...createNavItem(section, {
              items: appsToNavItems(apps),
            }),
          });
        }
      }

      return acc;
    }, []);
  };

  const appsToNavItems = (managementApps: ManagementApp[]) =>
    managementApps.map((app) => ({
      ...createNavItem(app, {
        ...reactRouterNavigate(history, app.basePath),
      }),
    }));

  interface HeaderWrapperProps {
    text: string;
    tip?: string;
  }

  const HeaderWrapper = ({ text, tip }: HeaderWrapperProps) => (
    <EuiFlexGroup alignItems="center" gutterSize="xs" responsive={false}>
      <EuiFlexItem grow={false}>{text}</EuiFlexItem>

      <EuiFlexItem grow={false}>
        <EuiIconTip content={tip} position="top" />
      </EuiFlexItem>
    </EuiFlexGroup>
  );

  const createNavItem = <T extends ManagementItem>(
    item: T,
    customParams: Partial<EuiSideNavItemType<any>> = {}
  ) => {
    const iconType = item.euiIconType || item.icon;

    return {
      id: item.id,
      name: item.tip ? <HeaderWrapper text={item.title} tip={item.tip} /> : item.title,
      isSelected: item.id === selectedId,
      icon: iconType ? <EuiIcon type={iconType} size="m" /> : undefined,
      'data-test-subj': item.id,
      ...customParams,
    };
  };

  return sectionsToNavItems(sections);
};
