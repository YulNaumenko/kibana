/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { UseMutationOptions, UseMutationResult } from '@tanstack/react-query';
import { useMutation } from '@tanstack/react-query';
import type { IHttpFetchError } from '@kbn/core-http-browser';
import type { UnisolationRouteRequestBody } from '../../../../common/api/endpoint';
import type { ResponseActionApiResponse } from '../../../../common/endpoint/types';
import { unIsolateHost } from '../../../common/lib/endpoint/endpoint_isolation';

/**
 * Create host release requests
 * @param customOptions
 */
export const useSendReleaseEndpointRequest = (
  customOptions?: UseMutationOptions<
    ResponseActionApiResponse,
    IHttpFetchError,
    UnisolationRouteRequestBody
  >
): UseMutationResult<ResponseActionApiResponse, IHttpFetchError, UnisolationRouteRequestBody> => {
  return useMutation<ResponseActionApiResponse, IHttpFetchError, UnisolationRouteRequestBody>(
    (releaseData: UnisolationRouteRequestBody) => {
      return unIsolateHost(releaseData);
    },
    customOptions
  );
};
