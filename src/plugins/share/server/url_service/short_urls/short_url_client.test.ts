/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { ServerShortUrlClientFactory } from './short_url_client_factory';
import { UrlService, LocatorDefinition } from '../../../common/url_service';
import { LegacyShortUrlLocatorDefinition } from '../../../common/url_service/locators/legacy_short_url_locator';
import { MemoryShortUrlStorage } from './storage/memory_short_url_storage';
import { SerializableRecord } from '@kbn/utility-types';
import { SavedObjectReference } from '@kbn/core/server';
import { UrlServiceError } from '../error';

const setup = () => {
  const currentVersion = '1.2.3';
  const service = new UrlService({
    getUrl: () => {
      throw new Error('Not implemented.');
    },
    navigate: () => {
      throw new Error('Not implemented.');
    },
    shortUrls: ({ locators }) =>
      new ServerShortUrlClientFactory({
        currentVersion,
        locators,
      }),
  });
  const definition = new LegacyShortUrlLocatorDefinition();
  const locator = service.locators.create(definition);
  const storage = new MemoryShortUrlStorage();
  const client = service.shortUrls.get({ storage });

  return {
    service,
    client,
    storage,
    locator,
    definition,
    currentVersion,
  };
};

const tick = (ms: number = 1) => new Promise((r) => setTimeout(r, ms));

const until = async (check: () => Promise<boolean>, pollInterval: number = 1) => {
  do {
    if (await check()) return;
    await tick(pollInterval);
  } while (true);
};

describe('ServerShortUrlClient', () => {
  describe('.create()', () => {
    test('can create a short URL', async () => {
      const { client, locator, currentVersion } = setup();
      const shortUrl = await client.create({
        locator,
        params: {
          url: '/app/test#foo/bar/baz',
        },
      });

      expect(shortUrl).toMatchObject({
        data: {
          accessCount: 0,
          accessDate: expect.any(Number),
          createDate: expect.any(Number),
          slug: expect.any(String),
          locator: {
            id: locator.id,
            version: currentVersion,
            state: {
              url: '/app/test#foo/bar/baz',
            },
          },
          id: expect.any(String),
        },
      });
    });

    test('initializes "accessDate" and "accessCount" fields on URL creation', async () => {
      const { client, locator } = setup();
      const { data } = await client.create({
        locator,
        slug: 'lala',
        params: {
          url: '/app/test#foo/bar/baz',
        },
      });

      expect(data.accessDate).toBeGreaterThan(Date.now() - 1000000);
      expect(data.accessCount).toBe(0);
    });
  });

  describe('.resolve()', () => {
    test('can get short URL by its slug', async () => {
      const { client, locator } = setup();
      const shortUrl1 = await client.create({
        locator,
        params: {
          url: '/app/test#foo/bar/baz',
        },
      });
      const shortUrl2 = await client.resolve(shortUrl1.data.slug);

      expect(shortUrl2.data).toStrictEqual(shortUrl1.data);
    });

    test('can create short URL with custom slug', async () => {
      const { client, locator } = setup();
      await client.create({
        locator,
        params: {
          url: '/app/test#foo/bar/baz',
        },
      });
      const shortUrl1 = await client.create({
        locator,
        slug: 'foo-bar',
        params: {
          url: '/app/test#foo/bar/baz',
        },
      });
      const shortUrl2 = await client.resolve('foo-bar');

      expect(shortUrl2.data).toMatchObject(shortUrl1.data);
    });

    test('cannot create short URL with the same slug', async () => {
      const { client, locator } = setup();
      await client.create({
        locator,
        slug: 'lala',
        params: {
          url: '/app/test#foo/bar/baz',
        },
      });

      await expect(
        client.create({
          locator,
          slug: 'lala',
          params: {
            url: '/app/test#foo/bar/baz',
          },
        })
      ).rejects.toThrowError(new UrlServiceError(`Slug "lala" already exists.`, 'SLUG_EXISTS'));
    });

    test('updates "accessCount" and "accessDate" on URL resolution by slug', async () => {
      const { client, locator } = setup();
      const shortUrl1 = await client.create({
        locator,
        params: {
          url: '/app/test#foo/bar/baz',
        },
      });

      expect(shortUrl1.data.accessDate).toBeGreaterThan(Date.now() - 1000000);
      expect(shortUrl1.data.accessCount).toBe(0);

      await client.resolve(shortUrl1.data.slug);
      await until(async () => (await client.get(shortUrl1.data.id)).data.accessCount === 1);
      const shortUrl2 = await client.get(shortUrl1.data.id);

      expect(shortUrl2.data.accessDate).toBeGreaterThanOrEqual(shortUrl1.data.accessDate);
      expect(shortUrl2.data.accessCount).toBe(1);

      await client.resolve(shortUrl1.data.slug);
      await until(async () => (await client.get(shortUrl1.data.id)).data.accessCount === 2);
      const shortUrl3 = await client.get(shortUrl1.data.id);

      expect(shortUrl3.data.accessDate).toBeGreaterThanOrEqual(shortUrl2.data.accessDate);
      expect(shortUrl3.data.accessCount).toBe(2);
    });
  });

  describe('.get()', () => {
    test('can fetch created short URL', async () => {
      const { client, locator } = setup();
      const shortUrl1 = await client.create({
        locator,
        params: {
          url: '/app/test#foo/bar/baz',
        },
      });
      const shortUrl2 = await client.get(shortUrl1.data.id);

      expect(shortUrl2.data).toStrictEqual(shortUrl1.data);
    });

    test('throws when fetching non-existing short URL', async () => {
      const { client } = setup();

      await expect(() => client.get('xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx')).rejects.toThrowError(
        new Error(`No short url with id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`)
      );
    });
  });

  describe('.delete()', () => {
    test('can delete an existing short URL', async () => {
      const { client, locator } = setup();
      const shortUrl1 = await client.create({
        locator,
        params: {
          url: '/app/test#foo/bar/baz',
        },
      });
      await client.delete(shortUrl1.data.id);

      await expect(() => client.get(shortUrl1.data.id)).rejects.toThrowError(
        new Error(`No short url with id "${shortUrl1.data.id}"`)
      );
    });
  });

  describe('Persistable State', () => {
    interface FooLocatorParams extends SerializableRecord {
      dashboardId: string;
      indexPatternId: string;
    }

    class FooLocatorDefinition implements LocatorDefinition<FooLocatorParams> {
      public readonly id = 'FOO_LOCATOR';

      public readonly getLocation = async () => ({
        app: 'foo_app',
        path: '/foo/path',
        state: {},
      });

      public readonly extract = (
        state: FooLocatorParams
      ): { state: FooLocatorParams; references: SavedObjectReference[] } => ({
        state,
        references: [
          {
            id: state.dashboardId,
            type: 'dashboard',
            name: 'dashboardId',
          },
          {
            id: state.indexPatternId,
            type: 'index_pattern',
            name: 'indexPatternId',
          },
        ],
      });

      public readonly inject = (
        state: FooLocatorParams,
        references: SavedObjectReference[]
      ): FooLocatorParams => {
        const dashboard = references.find(
          (ref) => ref.type === 'dashboard' && ref.name === 'dashboardId'
        );
        const indexPattern = references.find(
          (ref) => ref.type === 'index_pattern' && ref.name === 'indexPatternId'
        );

        return {
          ...state,
          dashboardId: dashboard ? dashboard.id : '',
          indexPatternId: indexPattern ? indexPattern.id : '',
        };
      };
    }

    test('extracts and persists references', async () => {
      const { service, client, storage } = setup();
      const locator = service.locators.create(new FooLocatorDefinition());
      const shortUrl = await client.create({
        locator,
        params: {
          dashboardId: '123',
          indexPatternId: '456',
        },
      });
      const record = await storage.getById(shortUrl.data.id);

      expect(record.references).toEqual([
        {
          id: '123',
          type: 'dashboard',
          name: 'locator:params:dashboardId',
        },
        {
          id: '456',
          type: 'index_pattern',
          name: 'locator:params:indexPatternId',
        },
      ]);
    });

    test('injects references', async () => {
      const { service, client, storage } = setup();
      const locator = service.locators.create(new FooLocatorDefinition());
      const shortUrl1 = await client.create({
        locator,
        params: {
          dashboardId: '3',
          indexPatternId: '5',
        },
      });
      const record1 = await storage.getById(shortUrl1.data.id);

      record1.data.locator.state = {};

      await storage.update(record1.data.id, record1.data);

      const record2 = await storage.getById(shortUrl1.data.id);

      expect(record2.data.locator.state).toEqual({});

      const shortUrl2 = await client.get(shortUrl1.data.id);

      expect(shortUrl2.data.locator.state).toEqual({
        dashboardId: '3',
        indexPatternId: '5',
      });
    });
  });
});
