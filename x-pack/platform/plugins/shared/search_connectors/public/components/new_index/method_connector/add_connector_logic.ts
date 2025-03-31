/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { kea, MakeLogicType } from 'kea';

import {
  AddConnectorApiLogic,
  AddConnectorApiLogicArgs,
  AddConnectorApiLogicResponse,
} from '../../../api/connector/add_connector_api_logic';
import { CONNECTOR_DETAIL_TAB_PATH } from '../../routes';
import { Actions } from '../../../api/api_logic/create_api_logic';
import { generateEncodedPath } from '../../shared/encode_path_params';
import { ErrorCode } from '../../../../common/types/error_codes';
import { SearchIndexTabId } from '../../../../common/constants';

type AddConnectorActions = Pick<
  Actions<AddConnectorApiLogicArgs, AddConnectorApiLogicResponse>,
  'apiError' | 'apiSuccess' | 'makeRequest' | 'apiReset'
> & {
  setIsModalVisible: (isModalVisible: boolean) => { isModalVisible: boolean };
};

export interface AddConnectorValues {
  isModalVisible: boolean;
}

export const AddConnectorLogic = kea<MakeLogicType<AddConnectorValues, AddConnectorActions>>({
  actions: {
    setIsModalVisible: (isModalVisible: boolean) => ({ isModalVisible }),
  },
  connect: {
    actions: [AddConnectorApiLogic, ['apiError', 'apiSuccess', 'makeRequest', 'apiReset']],
  },
  listeners: {
    apiSuccess: async ({ id, navigateToUrl }) => {
      if (navigateToUrl) {
        navigateToUrl(
          generateEncodedPath(`app/management/data/search_connectors${CONNECTOR_DETAIL_TAB_PATH}`, {
            connectorId: id,
            tabId: SearchIndexTabId.CONFIGURATION,
          })
        );
      }
    },
  },
  path: ['search_connectors', 'content', 'add_connector'],
  reducers: {
    isModalVisible: [
      false,
      {
        // @ts-expect-error upgrade typescript v5.1.6
        apiError: (_, error) =>
          error.body?.attributes?.error_code === ErrorCode.CONNECTOR_DOCUMENT_ALREADY_EXISTS,
        apiSuccess: () => false,
        // @ts-expect-error upgrade typescript v5.1.6
        setIsModalVisible: (_, { isModalVisible }) => isModalVisible,
      },
    ],
  },
});
