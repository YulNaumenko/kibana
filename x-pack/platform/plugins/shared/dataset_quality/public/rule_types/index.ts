/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { TriggersAndActionsUIPublicPluginSetup } from '@kbn/triggers-actions-ui-plugin/public';
import { getRuleType as getDegradedDocsRuleType } from './degraded_docs';

export function registerRuleTypes({
  ruleTypeRegistry,
}: {
  ruleTypeRegistry: TriggersAndActionsUIPublicPluginSetup['ruleTypeRegistry'];
}) {
  ruleTypeRegistry.register(getDegradedDocsRuleType());
}
