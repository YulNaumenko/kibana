/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';

import { EuiFlexGroup, EuiFlexItem, EuiFormRow, EuiPanel, EuiText } from '@elastic/eui';

import { i18n } from '@kbn/i18n';
import { ConfigEntryView, DisplayType } from './types';
import { ConnectorConfigurationField } from './connector_configuration_field';

interface ConnectorConfigurationFormItemsProps {
  isLoading: boolean;
  items: ConfigEntryView[];
  setConfigEntry: (key: string, value: string | number | boolean | null) => void;
  direction?: 'column' | 'row' | 'rowReverse' | 'columnReverse' | undefined;
  itemsGrow?: boolean;
}

export const ConnectorConfigurationFormItems: React.FC<ConnectorConfigurationFormItemsProps> = ({
  isLoading,
  items,
  setConfigEntry,
  direction,
  itemsGrow,
}) => {
  return (
    <EuiFlexGroup direction={direction}>
      {items.map((configEntry) => {
        const {
          default_value: defaultValue,
          depends_on: dependencies,
          key,
          display,
          isValid,
          label,
          sensitive,
          tooltip,
          validationErrors,
          required,
        } = configEntry;

        const helpText = defaultValue
          ? i18n.translate('searchConnectors.configurationConnector.config.defaultValue', {
              defaultMessage: 'Defaults to {defaultValue}',
              values: { defaultValue },
            })
          : tooltip;
        // toggle and sensitive textarea labels go next to the element, not in the row
        const rowLabel =
          display === DisplayType.TOGGLE || (display === DisplayType.TEXTAREA && sensitive) ? (
            <></>
          ) : tooltip ? (
            <EuiFlexGroup gutterSize="xs">
              <EuiFlexItem>
                <p>{label}</p>
              </EuiFlexItem>
            </EuiFlexGroup>
          ) : (
            <p>{label}</p>
          );

        const optionalLabel = !required ? (
          <EuiText color="subdued" size="xs">
            {i18n.translate('searchConnectors.configurationConnector.config.optionalValue', {
              defaultMessage: 'Optional',
            })}
          </EuiText>
        ) : undefined;

        if (dependencies?.length > 0) {
          return (
            <EuiFlexItem key={key} grow={itemsGrow}>
              <EuiPanel color="subdued" borderRadius="none">
                <EuiFormRow
                  fullWidth={true}
                  label={rowLabel}
                  helpText={helpText}
                  error={validationErrors}
                  isInvalid={!isValid}
                  labelAppend={optionalLabel}
                  data-test-subj={`entSearchContent-connector-configuration-formrow-${key}`}
                >
                  <ConnectorConfigurationField
                    configEntry={configEntry}
                    isLoading={isLoading}
                    setConfigValue={(value) => {
                      setConfigEntry(configEntry.key, value);
                    }}
                  />
                </EuiFormRow>
              </EuiPanel>
            </EuiFlexItem>
          );
        }
        return (
          <EuiFlexItem key={key}>
            <EuiFormRow
              label={rowLabel}
              fullWidth
              helpText={helpText}
              error={validationErrors}
              isInvalid={!isValid}
              labelAppend={optionalLabel}
              data-test-subj={`connector-configuration-formrow-${key}`}
            >
              <ConnectorConfigurationField
                configEntry={configEntry}
                isLoading={isLoading}
                setConfigValue={(value) => {
                  setConfigEntry(configEntry.key, value);
                }}
              />
            </EuiFormRow>
          </EuiFlexItem>
        );
      })}
    </EuiFlexGroup>
  );
};
