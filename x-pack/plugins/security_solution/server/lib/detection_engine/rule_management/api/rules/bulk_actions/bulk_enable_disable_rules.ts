/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { RulesClient } from '@kbn/alerting-plugin/server';
import { invariant } from '../../../../../../../common/utils/invariant';
import type { PromisePoolError } from '../../../../../../utils/promise_pool';
import type { MlAuthz } from '../../../../../machine_learning/authz';
import type { RuleAlertType } from '../../../../rule_schema';
import { validateBulkEnableRule } from '../../../logic/bulk_actions/validations';

interface BulkEnableDisableRulesArgs {
  rules: RuleAlertType[];
  action: 'enable' | 'disable';
  isDryRun?: boolean;
  rulesClient: RulesClient;
  mlAuthz: MlAuthz;
}

interface BulkEnableDisableRulesOutcome {
  updatedRules: RuleAlertType[];
  errors: Array<PromisePoolError<RuleAlertType, Error>>;
}

export const bulkEnableDisableRules = async ({
  rules,
  isDryRun,
  rulesClient,
  action: operation,
  mlAuthz,
}: BulkEnableDisableRulesArgs): Promise<BulkEnableDisableRulesOutcome> => {
  const errors: Array<PromisePoolError<RuleAlertType, Error>> = [];

  // In the first step, we validate if the rules can be enabled
  const validatedRules: RuleAlertType[] = [];
  await Promise.all(
    rules.map(async (rule) => {
      try {
        await validateBulkEnableRule({ mlAuthz, rule });
        validatedRules.push(rule);
      } catch (error) {
        errors.push({ item: rule, error });
      }
    })
  );

  if (isDryRun || validatedRules.length === 0) {
    return {
      updatedRules: validatedRules,
      errors,
    };
  }

  // Then if it's not a dry run, we enable the rules that passed the validation
  const ruleIds = validatedRules.map(({ id }) => id);

  // Perform actual update using the rulesClient
  const results =
    operation === 'enable'
      ? await rulesClient.bulkEnableRules({ ids: ruleIds })
      : await rulesClient.bulkDisableRules({ ids: ruleIds });

  // Rule objects returned from the bulkEnableRules are not
  // compatible with the response type. So we need to map them to
  // the original rules and update the enabled field
  errors.push(
    ...results.errors.map(({ rule: { id }, message }) => {
      const rule = rules.find((r) => r.id === id);
      invariant(rule != null, 'Unexpected rule id');
      return {
        item: rule,
        error: new Error(message),
      };
    })
  );

  return {
    updatedRules: results.rules as RuleAlertType[],
    errors,
  };
};
