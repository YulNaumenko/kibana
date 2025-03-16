/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React, { useEffect, useState } from 'react';

import { css } from '@emotion/react';

import { useHistory } from 'react-router-dom';

import {
  EuiBadge,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiIcon,
  EuiLink,
  EuiPanel,
  EuiSpacer,
  EuiSteps,
  EuiSuperSelect,
  EuiText,
  useEuiTheme,
} from '@elastic/eui';

import { EuiContainedStepProps } from '@elastic/eui/src/components/steps/steps';
import { i18n } from '@kbn/i18n';
import { useKibana } from '@kbn/kibana-react-plugin/public';
import { useUnsavedChangesPrompt } from '@kbn/unsaved-changes-prompt';

import { ScopedHistory } from '@kbn/core/public';
import { useActions, useValues } from 'kea';
import { KibanaPageTemplate } from '@kbn/shared-ux-page-kibana-template';
import { useAppContext } from '../../../app_context';
import { AddConnectorApiLogic } from '../../../api/connector/add_connector_api_logic';
import { NewConnectorLogic } from '../../new_index/method_connector/new_connector_logic';

import { generateStepState } from '../utils/generate_step_state';

import connectorsBackgroundImage from './assets/connector_logos_comp.png';

import { ConfigurationStep } from './configuration_step';
import { DeploymentStep } from './deployment_step';
import { FinishUpStep } from './finish_up_step';
import { StartStep } from './start_step';
import { errorToText } from '../utils/error_to_text';

export type ConnectorCreationSteps = 'start' | 'deployment' | 'configure' | 'finish';
export type SelfManagePreference = 'native' | 'selfManaged';
import '../../shared/page_template.scss';

export const CreateConnector: React.FC = () => {
  const {
    services: { overlays, http, application },
  } = useKibana();

  const history = useHistory();
  const { isAgentlessEnabled } = useAppContext();

  const { error } = useValues(AddConnectorApiLogic);
  const { euiTheme } = useEuiTheme();
  const [selfManagePreference, setSelfManagePreference] = useState<SelfManagePreference>('native');

  const { selectedConnector, currentStep, isFormDirty } = useValues(
    NewConnectorLogic({ http, navigateToUrl: application?.navigateToUrl })
  );
  const { setCurrentStep } = useActions(
    NewConnectorLogic({ http, navigateToUrl: application?.navigateToUrl })
  );
  const stepStates = generateStepState(currentStep);
  useEffect(() => {
    if (
      (selectedConnector && !selectedConnector.isNative && selfManagePreference === 'native') ||
      !isAgentlessEnabled
    ) {
      setSelfManagePreference('selfManaged');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedConnector]);

  const getSteps = (selfManaged: boolean): EuiContainedStepProps[] => {
    return [
      {
        children: null,
        status: stepStates.start,
        title: i18n.translate('xpack.searchConnectorscreateConnector.startStep.startLabel', {
          defaultMessage: 'Start',
        }),
      },
      ...(selfManaged
        ? [
            {
              children: null,
              status: stepStates.deployment,
              title: i18n.translate(
                'xpack.searchConnectorscreateConnector.deploymentStep.deploymentLabel',
                { defaultMessage: 'Deployment' }
              ),
            },
          ]
        : []),
      {
        children: null,
        status: stepStates.configure,
        title: i18n.translate(
          'xpack.searchConnectorscreateConnector.configurationStep.configurationLabel',
          { defaultMessage: 'Configuration' }
        ),
      },

      {
        children: null,
        status: stepStates.finish,
        title: i18n.translate('xpack.searchConnectorscreateConnector.finishUpStep.finishUpLabel', {
          defaultMessage: 'Finish up',
        }),
      },
    ];
  };

  const stepContent: Record<'start' | 'deployment' | 'configure' | 'finish', React.ReactNode> = {
    configure: (
      <ConfigurationStep
        title={i18n.translate(
          'xpack.searchConnectorscreateConnector.configurationStep.configurationLabel',
          { defaultMessage: 'Configuration' }
        )}
        setCurrentStep={setCurrentStep}
      />
    ),
    deployment: <DeploymentStep setCurrentStep={setCurrentStep} />,
    finish: (
      <FinishUpStep
        title={i18n.translate('xpack.searchConnectorscreateConnector.finishUpStep.finishUpLabel', {
          defaultMessage: 'Finish up',
        })}
      />
    ),
    start: (
      <StartStep
        title={i18n.translate('xpack.searchConnectorscreateConnector.startStep.startLabel', {
          defaultMessage: 'Start',
        })}
        selfManagePreference={selfManagePreference}
        setCurrentStep={setCurrentStep}
        onSelfManagePreferenceChange={(preference) => {
          setSelfManagePreference(preference);
        }}
        error={errorToText(error)}
      />
    ),
  };

  useUnsavedChangesPrompt({
    cancelButtonText: i18n.translate('xpack.searchConnectorscreateConnector.unsavedPrompt.cancel', {
      defaultMessage: 'Continue setup',
    }),
    confirmButtonText: i18n.translate(
      'xpack.searchConnectorscreateConnector.unsavedPrompt.confirm',
      {
        defaultMessage: 'Leave the page',
      }
    ),
    hasUnsavedChanges: isFormDirty,
    history: history as ScopedHistory,
    http: http!,
    messageText: i18n.translate('xpack.searchConnectorscreateConnector.unsavedPrompt.body', {
      defaultMessage:
        'Your connector is created but missing some details. You can complete the setup later in the connector configuration page, but this guided flow offers more help.',
    }),
    navigateToUrl: application!.navigateToUrl,
    openConfirm: overlays?.openConfirm ?? (() => Promise.resolve(false)),
    titleText: i18n.translate('xpack.searchConnectorscreateConnector.unsavedPrompt.title', {
      defaultMessage: 'Your connector is not fully configured',
    }),
  });

  return (
    <KibanaPageTemplate
      className={'searchConnectorsPageTemplate'}
      mainProps={{
        className: 'searchConnectorsPageTemplate__content',
      }}
      pageHeader={{
        description: i18n.translate('xpack.searchConnectorscreateConnector.description', {
          defaultMessage: 'Extract, transform, index and sync data from a third-party data source.',
        }),
        pageTitle: i18n.translate('xpack.searchConnectorscreateConnector..title', {
          defaultMessage: 'Create a connector',
        }),
      }}
    >
      <KibanaPageTemplate.Section>
        <EuiFlexGroup gutterSize="m">
          {/* Col 1 */}
          <EuiFlexItem grow={2}>
            <EuiPanel
              hasShadow={false}
              hasBorder
              color="subdued"
              paddingSize="l"
              css={css`
                ${currentStep === 'start'
                  ? `background-image: url(${connectorsBackgroundImage});`
                  : ''}
                background-size: contain;
                background-repeat: no-repeat;
                background-position: bottom center;
                min-height: 550px;
                border: 1px solid ${euiTheme.colors.lightShade};
              `}
            >
              <EuiSteps
                titleSize="xxs"
                steps={getSteps(selfManagePreference === 'selfManaged')}
                css={() => css`
                  .euiStep__content {
                    padding-block-end: ${euiTheme.size.xs};
                  }
                `}
              />
              <EuiSpacer size="xl" />
              {selectedConnector?.docsUrl && selectedConnector?.docsUrl !== '' && (
                <>
                  <EuiText size="s">
                    <p>
                      <EuiLink
                        external
                        data-test-subj="enterpriseSearchCreateConnectorConnectorDocsLink"
                        href={selectedConnector?.docsUrl}
                        target="_blank"
                      >
                        {'Elastic '}
                        {selectedConnector?.name}
                        {i18n.translate(
                          'xpack.searchConnectorscreateConnector.connectorDocsLinkLabel',
                          { defaultMessage: ' connector reference' }
                        )}
                      </EuiLink>
                    </p>
                  </EuiText>
                  <EuiSpacer size="s" />
                </>
              )}
              {currentStep !== 'start' && (
                <>
                  <EuiFormRow
                    label={i18n.translate(
                      'xpack.searchConnectorscreateConnector.euiFormRow.connectorLabel',
                      { defaultMessage: 'Connector' }
                    )}
                  >
                    <EuiSuperSelect
                      readOnly
                      valueOfSelected="item1"
                      options={[
                        {
                          inputDisplay: (
                            <>
                              <EuiIcon
                                size="l"
                                type={selectedConnector?.iconPath ?? ''}
                                css={css`
                                  margin-right: ${euiTheme.size.m};
                                `}
                              />
                              {selectedConnector?.name}
                            </>
                          ),
                          value: 'item1',
                        },
                      ]}
                    />
                  </EuiFormRow>
                  <EuiSpacer size="s" />
                  <EuiBadge color="hollow">
                    {selfManagePreference === 'selfManaged'
                      ? i18n.translate(
                          'xpack.searchConnectorscreateConnector.badgeType.selfManaged',
                          {
                            defaultMessage: 'Self-managed',
                          }
                        )
                      : i18n.translate(
                          'xpack.searchConnectorscreateConnector.badgeType.ElasticManaged',
                          {
                            defaultMessage: 'Elastic managed',
                          }
                        )}
                  </EuiBadge>
                </>
              )}
            </EuiPanel>
          </EuiFlexItem>
          {/* Col 2 */}
          <EuiFlexItem grow={7}>{stepContent[currentStep]}</EuiFlexItem>
        </EuiFlexGroup>
      </KibanaPageTemplate.Section>
    </KibanaPageTemplate>
  );
};
