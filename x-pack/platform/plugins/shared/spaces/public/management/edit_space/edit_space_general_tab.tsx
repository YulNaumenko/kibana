/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { EuiCallOut, EuiSpacer } from '@elastic/eui';
import React, { useCallback, useMemo, useState } from 'react';

import type { ScopedHistory } from '@kbn/core-application-browser';
import type { KibanaFeature } from '@kbn/features-plugin/common';
import { i18n } from '@kbn/i18n';
import { useUnsavedChangesPrompt } from '@kbn/unsaved-changes-prompt';

import { EditSpaceTabFooter } from './footer';
import { useEditSpaceServices } from './provider';
import type { Space } from '../../../common';
import { SOLUTION_VIEW_CLASSIC } from '../../../common/constants';
import { getSpaceInitials } from '../../space_avatar';
import { ConfirmDeleteModal } from '../components';
import { ConfirmAlterActiveSpaceModal } from '../components/confirm_alter_active_space_modal';
import { CustomizeAvatar } from '../components/customize_avatar';
import { CustomizeSpace } from '../components/customize_space';
import { EnabledFeatures } from '../components/enabled_features';
import { SolutionView } from '../components/solution_view';
import { SpaceValidator } from '../lib';
import type { CustomizeSpaceFormValues } from '../types';

interface Props {
  space: Space;
  history: ScopedHistory;
  features: KibanaFeature[];
  allowFeatureVisibility: boolean;
  allowSolutionVisibility: boolean;
  reloadWindow: () => void;
}

export const EditSpaceSettingsTab: React.FC<Props> = ({ space, features, history, ...props }) => {
  const imageAvatarSelected = Boolean(space.imageUrl);
  const [formValues, setFormValues] = useState<CustomizeSpaceFormValues>({
    ...space,
    avatarType: imageAvatarSelected ? 'image' : 'initials',
    imageUrl: imageAvatarSelected ? space.imageUrl : '',
  });

  // space initials are blank by default, they must be calculated
  const getSpaceFromFormValues = (newFormValues: CustomizeSpaceFormValues) => {
    return { ...newFormValues, initials: getSpaceInitials(newFormValues) };
  };

  const [isDirty, setIsDirty] = useState(false); // track if unsaved changes have been made
  const [isLoading, setIsLoading] = useState(false); // track if user has just clicked the Update button
  const [showUserImpactWarning, setShowUserImpactWarning] = useState(false);
  const [showAlteringActiveSpaceDialog, setShowAlteringActiveSpaceDialog] = useState(false);
  const [showConfirmDeleteModal, setShowConfirmDeleteModal] = useState(false);
  const { http, overlays, logger, notifications, navigateToUrl, spacesManager } =
    useEditSpaceServices();

  const [solution, setSolution] = useState<typeof space.solution | undefined>(space.solution);

  useUnsavedChangesPrompt({
    hasUnsavedChanges: isDirty,
    http,
    openConfirm: overlays.openConfirm,
    navigateToUrl,
    history,
    titleText: i18n.translate('xpack.spaces.management.spaceDetails.unsavedChangesPromptTitle', {
      defaultMessage: 'Leave without saving?',
    }),
    messageText: i18n.translate(
      'xpack.spaces.management.spaceDetails.unsavedChangesPromptMessage',
      {
        defaultMessage: "Unsaved changes won't be applied to the space and will be lost.",
      }
    ),
    cancelButtonText: i18n.translate('xpack.spaces.management.spaceDetails.keepEditingButton', {
      defaultMessage: 'Save before leaving',
    }),
    confirmButtonText: i18n.translate('xpack.spaces.management.spaceDetails.leavePageButton', {
      defaultMessage: 'Leave',
    }),
  });

  const onChangeSpaceSettings = useCallback(
    (newFormValues: CustomizeSpaceFormValues) => {
      setFormValues({ ...formValues, ...newFormValues });
      setIsDirty(true);
    },
    [formValues]
  );

  const onChangeFeatures = useCallback(
    (updatedSpace: Partial<Space>) => {
      setFormValues({ ...formValues, ...updatedSpace });
      setIsDirty(true);
      setShowUserImpactWarning(true);
    },
    [formValues]
  );

  const onSolutionViewChange = useCallback(
    (updatedSpace: Partial<Space>) => {
      setSolution(updatedSpace.solution);
      onChangeFeatures(updatedSpace);
    },
    [onChangeFeatures]
  );

  const backToSpacesList = useCallback(() => {
    history.push('/');
  }, [history]);

  const onClickCancel = useCallback(() => {
    setShowAlteringActiveSpaceDialog(false);
    setShowUserImpactWarning(false);
    backToSpacesList();
  }, [backToSpacesList]);

  const onClickDeleteSpace = useCallback(() => {
    setShowConfirmDeleteModal(true);
  }, []);

  const performSave = useCallback(
    async ({ requiresReload = false }) => {
      const {
        avatarType,
        customIdentifier,
        customAvatarColor,
        customAvatarInitials,
        ...partialSpace
      } = formValues;

      const spaceClone = structuredClone(partialSpace as Partial<Space>);
      const { id, name } = spaceClone;

      if (!id) {
        throw new Error(`Can not update space without id field!`);
      }
      if (!name) {
        throw new Error(`Can not update space without name field!`);
      }

      setIsLoading(true);

      let disabledFeatures: string[] | undefined;
      if (!spaceClone.solution || spaceClone.solution === SOLUTION_VIEW_CLASSIC) {
        disabledFeatures = spaceClone.disabledFeatures;
      }

      try {
        await spacesManager.updateSpace({
          ...spaceClone,
          id,
          name,
          disabledFeatures: disabledFeatures ?? [],
          imageUrl: avatarType === 'image' ? spaceClone.imageUrl : '',
        });

        notifications.toasts.addSuccess(
          i18n.translate(
            'xpack.spaces.management.spaceDetails.spaceSuccessfullySavedNotificationMessage',
            {
              defaultMessage: 'Space "{name}" was saved.',
              values: { name },
            }
          )
        );

        setIsDirty(false);
        backToSpacesList();
        if (requiresReload) {
          props.reloadWindow();
        }
      } catch (error) {
        logger.error('Could not save changes to space!', error);
        const message = error?.body?.message ?? error.toString();
        notifications.toasts.addError(error, {
          title: i18n.translate('xpack.spaces.management.spaceDetails.errorSavingSpaceTitle', {
            defaultMessage: 'Error saving space: {message}',
            values: { message },
          }),
        });
      } finally {
        setIsLoading(false);
      }
    },
    [backToSpacesList, notifications.toasts, formValues, spacesManager, logger, props]
  );

  const validator = useMemo(() => new SpaceValidator(), []);

  const onClickSubmit = useCallback(() => {
    validator.enableValidation();
    const validationResult = validator.validateForSave(
      formValues,
      true,
      props.allowSolutionVisibility
    );

    if (validationResult.isInvalid) {
      // invalid form input fields will show the error message
      return;
    }

    if (showUserImpactWarning) {
      setShowAlteringActiveSpaceDialog(true);
    } else {
      performSave({ requiresReload: false });
    }
  }, [validator, formValues, props.allowSolutionVisibility, performSave, showUserImpactWarning]);

  const doShowAlteringActiveSpaceDialog = () => {
    return (
      showAlteringActiveSpaceDialog && (
        <ConfirmAlterActiveSpaceModal
          onConfirm={() => performSave({ requiresReload: true })}
          onCancel={() => {
            setShowAlteringActiveSpaceDialog(false);
          }}
        />
      )
    );
  };

  const doShowConfirmDeleteSpaceDialog = () => {
    return (
      showConfirmDeleteModal && (
        <ConfirmDeleteModal
          space={space}
          spacesManager={spacesManager}
          onCancel={() => {
            setShowConfirmDeleteModal(false);
          }}
          onSuccess={() => {
            setShowConfirmDeleteModal(false);
            backToSpacesList();
          }}
        />
      )
    );
  };

  // Show if user has changed disabled features
  // Show if user has changed solution view
  const doShowUserImpactWarning = () => {
    return (
      showUserImpactWarning && (
        <>
          <EuiSpacer />
          <EuiCallOut
            color="warning"
            iconType="info"
            title={i18n.translate(
              'xpack.spaces.management.spaceDetails.spaceChangesWarning.impactAllUsersInSpace',
              {
                defaultMessage: 'The changes will apply to all users of the space.',
              }
            )}
            data-test-subj="space-edit-page-user-impact-warning"
          />
        </>
      )
    );
  };

  return (
    <>
      {doShowAlteringActiveSpaceDialog()}
      {doShowConfirmDeleteSpaceDialog()}

      <CustomizeSpace
        space={getSpaceFromFormValues(formValues)}
        onChange={onChangeSpaceSettings}
        editingExistingSpace={true}
        validator={validator}
      />

      {props.allowSolutionVisibility && (
        <>
          <EuiSpacer />
          <SolutionView
            space={getSpaceFromFormValues(formValues)}
            onChange={onSolutionViewChange}
            validator={validator}
            isEditing={true}
          />
        </>
      )}

      {props.allowFeatureVisibility && (!solution || solution === SOLUTION_VIEW_CLASSIC) && (
        <>
          <EuiSpacer />
          <EnabledFeatures
            features={features}
            space={getSpaceFromFormValues(formValues)}
            onChange={onChangeFeatures}
          />
        </>
      )}

      <EuiSpacer />

      <CustomizeAvatar
        space={getSpaceFromFormValues(formValues)}
        onChange={onChangeSpaceSettings}
        validator={validator}
      />

      {doShowUserImpactWarning()}

      <EuiSpacer />
      <EditSpaceTabFooter
        isDirty={isDirty}
        isLoading={isLoading}
        onClickCancel={onClickCancel}
        onClickSubmit={onClickSubmit}
        onClickDeleteSpace={onClickDeleteSpace}
      />
    </>
  );
};
