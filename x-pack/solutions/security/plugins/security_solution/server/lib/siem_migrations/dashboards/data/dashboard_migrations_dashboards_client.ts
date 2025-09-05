/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type {
  AggregationsMaxAggregate,
  AggregationsMinAggregate,
  AggregationsStringTermsAggregate,
  AggregationsStringTermsBucket,
  QueryDslQueryContainer,
} from '@elastic/elasticsearch/lib/api/types';
import { MigrationTaskStatusEnum } from '../../../../../common/siem_migrations/model/common.gen';
import { SiemMigrationStatus } from '../../../../../common/siem_migrations/constants';
import { SiemMigrationsDataBaseClient } from '../../common/data/siem_migrations_data_base_client';
import {
  type DashboardMigrationDashboard,
  type DashboardMigrationTaskStats,
} from '../../../../../common/siem_migrations/model/dashboard_migration.gen';
import type { CreateMigrationItemInput } from '../../common/data/siem_migrations_data_item_client';

/* BULK_MAX_SIZE defines the number to break down the bulk operations by.
 * The 500 number was chosen as a reasonable number to avoid large payloads. It can be adjusted if needed. */
const BULK_MAX_SIZE = 500 as const;

export class DashboardMigrationsDataDashboardsClient extends SiemMigrationsDataBaseClient {
  /** Indexes an array of dashboards to be processed as a part of single migration */
  async create(
    migrationId: string,
    dashboardsInput: CreateMigrationItemInput<DashboardMigrationDashboard>[]
  ): Promise<void> {
    const index = await this.getIndexName();
    const profileId = await this.getProfileUid();

    let originalDashboardsMaxBatch: CreateMigrationItemInput<DashboardMigrationDashboard>[];
    const createdAt = new Date().toISOString();
    const dashboardsToBeAdded = structuredClone(dashboardsInput);
    while ((originalDashboardsMaxBatch = dashboardsToBeAdded.splice(0, BULK_MAX_SIZE)).length) {
      await this.esClient
        .bulk<DashboardMigrationDashboard>({
          refresh: 'wait_for',
          operations: originalDashboardsMaxBatch.flatMap((dashboardInput) => [
            { create: { _index: index } },
            {
              '@timestamp': createdAt,
              status: SiemMigrationStatus.PENDING,
              created_by: profileId,
              updated_by: profileId,
              updated_at: createdAt,
              ...dashboardInput,
            },
          ]),
        })
        .catch((error) => {
          this.logger.error(
            `Error adding dashboards to migration (id:${migrationId}) : ${error.message}`
          );
          throw error;
        });
    }
  }

  /** Updates dashboard migration documents */
  async update(updates: Array<Partial<DashboardMigrationDashboard>>): Promise<void> {
    if (updates.length === 0) {
      return;
    }

    const index = await this.getIndexName();
    const profileId = await this.getProfileUid();
    const updatedAt = new Date().toISOString();

    const operations = updates.flatMap((update) => [
      { update: { _index: index, _id: update.id } },
      {
        ...Object.fromEntries(Object.entries(update).filter(([key]) => key !== 'id')),
        updated_by: profileId,
        updated_at: updatedAt,
      },
    ]);

    await this.esClient
      .bulk({
        refresh: 'wait_for',
        operations,
      })
      .catch((error) => {
        this.logger.error(`Error updating dashboards: ${error.message}`);
        throw error;
      });
  }

  async getStats(migrationId: string): Promise<Omit<DashboardMigrationTaskStats, 'name'>> {
    const index = await this.getIndexName();

    const migrationIdFilter: QueryDslQueryContainer = { term: { migration_id: migrationId } };
    const query = {
      bool: {
        filter: migrationIdFilter,
      },
    };
    const aggregations = {
      status: { terms: { field: 'status' } },
      createdAt: { min: { field: '@timestamp' } },
      lastUpdatedAt: { max: { field: 'updated_at' } },
    };
    const result = await this.esClient
      .search({ index, query, aggregations, _source: false })
      .catch((error) => {
        this.logger.error(`Error getting dashboard migration stats: ${error.message}`);
        throw error;
      });

    const aggs = result.aggregations ?? {};

    return {
      id: migrationId,
      items: {
        total: this.getTotalHits(result),
        ...this.statusAggCounts(aggs.status as AggregationsStringTermsAggregate),
      },
      created_at: (aggs.createdAt as AggregationsMinAggregate)?.value_as_string ?? '',
      last_updated_at: (aggs.lastUpdatedAt as AggregationsMaxAggregate)?.value_as_string ?? '',
      status: MigrationTaskStatusEnum.ready,
    };
  }

  private statusAggCounts(
    statusAgg: AggregationsStringTermsAggregate
  ): Record<SiemMigrationStatus, number> {
    const buckets = statusAgg.buckets as AggregationsStringTermsBucket[];
    return {
      [SiemMigrationStatus.PENDING]:
        buckets.find(({ key }) => key === SiemMigrationStatus.PENDING)?.doc_count ?? 0,
      [SiemMigrationStatus.PROCESSING]:
        buckets.find(({ key }) => key === SiemMigrationStatus.PROCESSING)?.doc_count ?? 0,
      [SiemMigrationStatus.COMPLETED]:
        buckets.find(({ key }) => key === SiemMigrationStatus.COMPLETED)?.doc_count ?? 0,
      [SiemMigrationStatus.FAILED]:
        buckets.find(({ key }) => key === SiemMigrationStatus.FAILED)?.doc_count ?? 0,
    };
  }
}
