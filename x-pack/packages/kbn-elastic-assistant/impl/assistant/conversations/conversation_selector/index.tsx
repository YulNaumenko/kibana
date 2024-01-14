/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  EuiButtonIcon,
  EuiComboBox,
  EuiComboBoxOptionOption,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFormRow,
  EuiHighlight,
  EuiToolTip,
} from '@elastic/eui';
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import useEvent from 'react-use/lib/useEvent';
import { css } from '@emotion/react';

import { OpenAiProviderType } from '@kbn/stack-connectors-plugin/common/openai/constants';
import { merge } from 'lodash';
import { Conversation, useFetchCurrentUserConversations } from '../../../..';
import { useAssistantContext } from '../../../assistant_context';
import * as i18n from './translations';
import { DEFAULT_CONVERSATION_TITLE } from '../../use_conversation/translations';
import { useConversation } from '../../use_conversation';
import { SystemPromptSelectorOption } from '../../prompt_editor/system_prompt/system_prompt_modal/system_prompt_selector/system_prompt_selector';

const isMac = navigator.platform.toLowerCase().indexOf('mac') >= 0;

interface Props {
  defaultConnectorId?: string;
  defaultProvider?: OpenAiProviderType;
  selectedConversationId: string | undefined;
  onConversationSelected: (conversationId: string) => void;
  shouldDisableKeyboardShortcut?: () => boolean;
  isDisabled?: boolean;
}

const getPreviousConversationId = (conversationIds: string[], selectedConversationId: string) => {
  return conversationIds.indexOf(selectedConversationId) === 0
    ? conversationIds[conversationIds.length - 1]
    : conversationIds[conversationIds.indexOf(selectedConversationId) - 1];
};

const getNextConversationId = (conversationIds: string[], selectedConversationId: string) => {
  return conversationIds.indexOf(selectedConversationId) + 1 >= conversationIds.length
    ? conversationIds[0]
    : conversationIds[conversationIds.indexOf(selectedConversationId) + 1];
};

export type ConversationSelectorOption = EuiComboBoxOptionOption<{
  isDefault: boolean;
}>;

export const ConversationSelector: React.FC<Props> = React.memo(
  ({
    selectedConversationId = DEFAULT_CONVERSATION_TITLE,
    defaultConnectorId,
    defaultProvider,
    onConversationSelected,
    shouldDisableKeyboardShortcut = () => false,
    isDisabled = false,
  }) => {
    const [conversations, setConversations] = useState<Record<string, Conversation>>({});
    const { allSystemPrompts, baseConversations } = useAssistantContext();

    const { deleteConversation, createConversation } = useConversation();

    const { data: conversationsData, isLoading } = useFetchCurrentUserConversations();

    useEffect(() => {
      if (!isLoading) {
        const userConversations = (conversationsData?.data ?? []).reduce<
          Record<string, Conversation>
        >((transformed, conversation) => {
          transformed[conversation.id] = conversation;
          return transformed;
        }, {});
        setConversations(
          merge(
            userConversations,
            Object.keys(baseConversations)
              .filter(
                (baseId) =>
                  (conversationsData?.data ?? []).find((c) => c.title === baseId) === undefined
              )
              .reduce<Record<string, Conversation>>((transformed, conversation) => {
                transformed[conversation] = baseConversations[conversation];
                return transformed;
              }, {})
          )
        );
      }
    }, [baseConversations, conversationsData?.data, isLoading]);

    const conversationIds = useMemo(() => Object.keys(conversations), [conversations]);
    const conversationOptions = useMemo<ConversationSelectorOption[]>(() => {
      return Object.values(conversations).map((conversation) => ({
        value: { isDefault: conversation.isDefault ?? false },
        id: conversation.id ?? conversation.title,
        label: conversation.title,
      }));
    }, [conversations]);

    const [selectedOptions, setSelectedOptions] = useState<ConversationSelectorOption[]>(() => {
      return conversationOptions.filter((c) => c.id === selectedConversationId) ?? [];
    });

    // Callback for when user types to create a new system prompt
    const onCreateOption = useCallback(
      async (searchValue, flattenedOptions = []) => {
        if (!searchValue || !searchValue.trim().toLowerCase()) {
          return;
        }

        const normalizedSearchValue = searchValue.trim().toLowerCase();
        const defaultSystemPrompt = allSystemPrompts.find(
          (systemPrompt) => systemPrompt.isNewConversationDefault
        );
        const optionExists =
          flattenedOptions.findIndex(
            (option: SystemPromptSelectorOption) =>
              option.label.trim().toLowerCase() === normalizedSearchValue
          ) !== -1;

        let cId;
        if (!optionExists) {
          const newConversation: Conversation = {
            id: searchValue,
            title: searchValue,
            messages: [],
            apiConfig: {
              connectorId: defaultConnectorId,
              provider: defaultProvider,
              defaultSystemPromptId: defaultSystemPrompt?.id,
            },
          };
          cId = (await createConversation(newConversation))?.id;
        }
        onConversationSelected(cId ?? DEFAULT_CONVERSATION_TITLE);
      },
      [
        allSystemPrompts,
        onConversationSelected,
        defaultConnectorId,
        defaultProvider,
        createConversation,
      ]
    );

    // Callback for when user deletes a conversation
    const onDelete = useCallback(
      (cId: string) => {
        if (selectedConversationId === cId) {
          onConversationSelected(getPreviousConversationId(conversationIds, cId));
        }
        setTimeout(() => {
          deleteConversation(cId);
        }, 0);
        const deletedConv = { ...conversations };
        delete deletedConv[cId];
        setConversations(deletedConv);
      },
      [
        selectedConversationId,
        conversations,
        onConversationSelected,
        conversationIds,
        deleteConversation,
      ]
    );

    const onChange = useCallback(
      (newOptions: ConversationSelectorOption[]) => {
        if (newOptions.length === 0 || !newOptions?.[0].id) {
          setSelectedOptions([]);
        } else if (conversationOptions.findIndex((o) => o.id === newOptions?.[0].id) !== -1) {
          onConversationSelected(newOptions?.[0].id);
        }
      },
      [conversationOptions, onConversationSelected]
    );

    const onLeftArrowClick = useCallback(() => {
      const prevId = getPreviousConversationId(conversationIds, selectedConversationId);
      onConversationSelected(prevId);
    }, [conversationIds, selectedConversationId, onConversationSelected]);
    const onRightArrowClick = useCallback(() => {
      const nextId = getNextConversationId(conversationIds, selectedConversationId);
      onConversationSelected(nextId);
    }, [conversationIds, selectedConversationId, onConversationSelected]);

    // Register keyboard listener for quick conversation switching
    const onKeyDown = useCallback(
      (event: KeyboardEvent) => {
        if (isDisabled || conversationIds.length <= 1) {
          return;
        }

        if (
          event.key === 'ArrowLeft' &&
          (isMac ? event.metaKey : event.ctrlKey) &&
          !shouldDisableKeyboardShortcut()
        ) {
          event.preventDefault();
          onLeftArrowClick();
        }
        if (
          event.key === 'ArrowRight' &&
          (isMac ? event.metaKey : event.ctrlKey) &&
          !shouldDisableKeyboardShortcut()
        ) {
          event.preventDefault();
          onRightArrowClick();
        }
      },
      [
        conversationIds.length,
        isDisabled,
        onLeftArrowClick,
        onRightArrowClick,
        shouldDisableKeyboardShortcut,
      ]
    );
    useEvent('keydown', onKeyDown);

    useEffect(() => {
      setSelectedOptions(conversationOptions.filter((c) => c.id === selectedConversationId));
    }, [conversationOptions, selectedConversationId]);

    const renderOption: (
      option: ConversationSelectorOption,
      searchValue: string,
      OPTION_CONTENT_CLASSNAME: string
    ) => React.ReactNode = (option, searchValue, contentClassName) => {
      const { label, value, id } = option;
      return (
        <EuiFlexGroup
          alignItems="center"
          className={'parentFlexGroup'}
          component={'span'}
          justifyContent="spaceBetween"
          data-test-subj={`convo-option-${label}`}
        >
          <EuiFlexItem
            component={'span'}
            grow={false}
            css={css`
              width: calc(100% - 60px);
            `}
          >
            <EuiHighlight
              search={searchValue}
              css={css`
                overflow: hidden;
                text-overflow: ellipsis;
              `}
            >
              {label}
            </EuiHighlight>
          </EuiFlexItem>
          {!value?.isDefault && (
            <EuiFlexItem grow={false} component={'span'}>
              <EuiToolTip position="right" content={i18n.DELETE_CONVERSATION}>
                <EuiButtonIcon
                  iconType="cross"
                  aria-label={i18n.DELETE_CONVERSATION}
                  color="danger"
                  onClick={(e: React.MouseEvent) => {
                    e.stopPropagation();
                    onDelete(id ?? '');
                  }}
                  data-test-subj="delete-option"
                  css={css`
                    visibility: hidden;
                    .parentFlexGroup:hover & {
                      visibility: visible;
                    }
                  `}
                />
              </EuiToolTip>
            </EuiFlexItem>
          )}
        </EuiFlexGroup>
      );
    };

    return (
      <EuiFormRow
        label={i18n.SELECTED_CONVERSATION_LABEL}
        display="rowCompressed"
        css={css`
          min-width: 300px;
        `}
      >
        <EuiComboBox
          data-test-subj="conversation-selector"
          aria-label={i18n.CONVERSATION_SELECTOR_ARIA_LABEL}
          customOptionText={`${i18n.CONVERSATION_SELECTOR_CUSTOM_OPTION_TEXT} {searchValue}`}
          placeholder={i18n.CONVERSATION_SELECTOR_PLACE_HOLDER}
          singleSelection={{ asPlainText: true }}
          options={conversationOptions}
          selectedOptions={selectedOptions}
          onChange={onChange}
          onCreateOption={onCreateOption as unknown as () => void}
          renderOption={renderOption}
          compressed={true}
          isDisabled={isDisabled}
          prepend={
            <EuiToolTip content={`${i18n.PREVIOUS_CONVERSATION_TITLE} (⌘ + ←)`} display="block">
              <EuiButtonIcon
                iconType="arrowLeft"
                aria-label={i18n.PREVIOUS_CONVERSATION_TITLE}
                onClick={onLeftArrowClick}
                disabled={isDisabled || conversationIds.length <= 1}
              />
            </EuiToolTip>
          }
          append={
            <EuiToolTip content={`${i18n.NEXT_CONVERSATION_TITLE} (⌘ + →)`} display="block">
              <EuiButtonIcon
                iconType="arrowRight"
                aria-label={i18n.NEXT_CONVERSATION_TITLE}
                onClick={onRightArrowClick}
                disabled={isDisabled || conversationIds.length <= 1}
              />
            </EuiToolTip>
          }
        />
      </EuiFormRow>
    );
  }
);

ConversationSelector.displayName = 'ConversationSelector';
