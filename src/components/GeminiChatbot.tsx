import React, { useState, useEffect, useRef } from 'react';
import {
  Send,
  Plus,
  Trash2,
  Bot,
  User as UserIcon,
  Sliders,
  Sparkles,
  Zap,
  Brain,
  AlertCircle,
  RefreshCw,
  MessageSquare,
} from 'lucide-react';
import {
  auth,
  onAuthStateChanged,
  subscribeChatThreads,
  subscribeChatMessages,
  createChatThreadInFirestore,
  updateChatThreadInFirestore,
  deleteChatThreadInFirestore,
  addChatMessageInFirestore,
  FirestoreChatThread,
  ChatRolePreset,
  GeminiChatModel,
} from '../lib/firebase/client.js';

interface ChatTurn {
  id: string;
  role: 'user' | 'model';
  text: string;
  model?: GeminiChatModel;
  createdAt: string;
}

interface GeminiChatbotProps {
  recentAlertsSummary?: string;
}

const ROLE_PRESETS: Record<
  ChatRolePreset,
  {
    label: string;
    description: string;
    systemInstruction: string;
    defaultMode: 'standard' | 'deep' | 'fast';
  }
> = {
  sentinel_analyst: {
    label: 'Security Sentinel Analyst',
    description: 'Root-cause analysis of security alerts, CVEs, and quarantined payloads',
    systemInstruction:
      'You are Aegis Sentinel Analyst, an expert cybersecurity triage assistant. Analyze security alerts, explain root causes clearly, assess severity, and recommend concrete defensive actions.',
    defaultMode: 'deep',
  },
  incident_responder: {
    label: 'Incident Responder',
    description: 'Step-by-step containment, SLA escalation, and outage mitigation',
    systemInstruction:
      'You are Aegis Incident Responder. Provide crisp, numbered incident containment playbooks, escalation checklists, and verification steps for production outages and security incidents.',
    defaultMode: 'standard',
  },
  policy_advisor: {
    label: 'Alert Policy Advisor',
    description: 'Helps configure DND quiet hours, fallback channels, and noise filters',
    systemInstruction:
      'You are Aegis Alert Policy Advisor. Help users configure notification priority thresholds, quiet hours, WebSocket/Email/SMS fallback SLAs, and deduplication rules without missing critical alerts.',
    defaultMode: 'standard',
  },
  fast_triage: {
    label: 'Fast Triage Assistant',
    description: 'Ultra-fast concise summaries and quick answers',
    systemInstruction:
      'You are Aegis Fast Triage Assistant. Reply in concise bullet points under 120 words focused on immediate next actions.',
    defaultMode: 'fast',
  },
  custom: {
    label: 'Custom Persona',
    description: 'Use your own custom system instruction',
    systemInstruction:
      'You are a helpful, accurate AI assistant inside AegisNotify Engine.',
    defaultMode: 'standard',
  },
};

export default function GeminiChatbot({ recentAlertsSummary }: GeminiChatbotProps) {
  const [firebaseUid, setFirebaseUid] = useState<string | null>(() => auth.currentUser?.uid || null);
  const [threads, setThreads] = useState<FirestoreChatThread[]>([]);
  const [activeThreadId, setActiveThreadId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatTurn[]>([]);
  const [inputText, setInputText] = useState('');
  const [rolePreset, setRolePreset] = useState<ChatRolePreset>('sentinel_analyst');
  const [systemInstruction, setSystemInstruction] = useState(
    ROLE_PRESETS.sentinel_analyst.systemInstruction
  );
  const [reasoningMode, setReasoningMode] = useState<'standard' | 'deep' | 'fast'>('standard');
  const [showSystemEditor, setShowSystemEditor] = useState(false);
  const [includeAlertsContext, setIncludeAlertsContext] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const threadEndRef = useRef<HTMLDivElement | null>(null);

  const activeModel: GeminiChatModel =
    reasoningMode === 'fast' ? 'gemini-3.1-flash-lite' : 'gemini-4-hydrogen';

  useEffect(() => {
    const unsub = onAuthStateChanged(auth, (u) => {
      setFirebaseUid(u ? u.uid : null);
    });
    return () => unsub();
  }, []);

  // Subscribe to user's saved Firestore threads when signed in with Firebase Auth
  useEffect(() => {
    if (!firebaseUid) {
      setThreads([]);
      return;
    }
    const unsub = subscribeChatThreads(
      firebaseUid,
      (list) => {
        setThreads(list);
        if (list.length > 0 && !activeThreadId) {
          const first = list[0];
          setActiveThreadId(first.id);
          setRolePreset(first.rolePreset);
          setSystemInstruction(first.systemInstruction);
          setReasoningMode(first.model === 'gemini-3.1-flash-lite' ? 'fast' : 'standard');
        }
      },
      (err) => {
        setErrorMsg(err.message);
      }
    );
    return () => unsub();
  }, [firebaseUid]);

  // Subscribe to messages for the active Firestore thread
  useEffect(() => {
    if (!firebaseUid || !activeThreadId) return;
    const unsub = subscribeChatMessages(
      firebaseUid,
      activeThreadId,
      (list) => {
        setMessages(
          list.map((m) => ({
            id: m.id,
            role: m.role,
            text: m.text,
            model: m.model,
            createdAt: m.createdAt ? m.createdAt.toISOString() : new Date().toISOString(),
          }))
        );
      },
      (err) => {
        setErrorMsg(err.message);
      }
    );
    return () => unsub();
  }, [firebaseUid, activeThreadId]);

  useEffect(() => {
    threadEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isSending]);

  const handleRoleChange = async (nextRole: ChatRolePreset) => {
    const preset = ROLE_PRESETS[nextRole];
    setRolePreset(nextRole);
    setSystemInstruction(preset.systemInstruction);
    setReasoningMode(preset.defaultMode);

    if (firebaseUid && activeThreadId) {
      try {
        await updateChatThreadInFirestore(firebaseUid, activeThreadId, {
          rolePreset: nextRole,
          systemInstruction: preset.systemInstruction,
          model: preset.defaultMode === 'fast' ? 'gemini-3.1-flash-lite' : 'gemini-4-hydrogen',
        });
      } catch (err: any) {
        setErrorMsg(err.message);
      }
    }
  };

  const handleNewChat = async () => {
    setErrorMsg(null);
    if (!firebaseUid) {
      setActiveThreadId(null);
      setMessages([]);
      return;
    }

    try {
      const newId = await createChatThreadInFirestore(firebaseUid, {
        title: `${ROLE_PRESETS[rolePreset].label} Chat`,
        rolePreset,
        systemInstruction,
        model: activeModel,
      });
      setActiveThreadId(newId);
      setMessages([]);
    } catch (err: any) {
      setErrorMsg(err.message || 'Could not create chat thread.');
    }
  };

  const handleSelectThread = (thread: FirestoreChatThread) => {
    setErrorMsg(null);
    setActiveThreadId(thread.id);
    setRolePreset(thread.rolePreset);
    setSystemInstruction(thread.systemInstruction);
    setReasoningMode(thread.model === 'gemini-3.1-flash-lite' ? 'fast' : 'standard');
  };

  const handleDeleteThread = async (threadId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!firebaseUid) return;
    try {
      await deleteChatThreadInFirestore(firebaseUid, threadId);
      if (activeThreadId === threadId) {
        setActiveThreadId(null);
        setMessages([]);
      }
    } catch (err: any) {
      setErrorMsg(err.message);
    }
  };

  const handleSendMessage = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const trimmed = inputText.trim();
    if (!trimmed || isSending) return;

    setErrorMsg(null);
    setIsSending(true);
    setInputText('');

    const effectiveSystemInstruction =
      includeAlertsContext && recentAlertsSummary
        ? `${systemInstruction}\n\nCurrent live dashboard alerts summary:\n${recentAlertsSummary}`
        : systemInstruction;

    const historySnapshot = messages.slice(-24).map((m) => ({
      role: m.role,
      text: m.text,
    }));

    let threadIdToUse = activeThreadId;

    try {
      // If signed into Firebase Auth and no thread exists yet, create one in Firestore
      if (firebaseUid && !threadIdToUse) {
        threadIdToUse = await createChatThreadInFirestore(firebaseUid, {
          title: trimmed.slice(0, 60),
          rolePreset,
          systemInstruction,
          model: activeModel,
        });
        setActiveThreadId(threadIdToUse);
      }

      if (firebaseUid && threadIdToUse) {
        await addChatMessageInFirestore(firebaseUid, threadIdToUse, {
          role: 'user',
          text: trimmed,
          model: activeModel,
        });
      } else {
        setMessages((prev) => [
          ...prev,
          {
            id: `usr_${Date.now()}`,
            role: 'user',
            text: trimmed,
            model: activeModel,
            createdAt: new Date().toISOString(),
          },
        ]);
      }

      const authToken =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      const customFocusText =
        systemInstruction !== ROLE_PRESETS[rolePreset].systemInstruction
          ? systemInstruction.slice(0, 400)
          : undefined;

      const res = await fetch('/api/v1/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
        body: JSON.stringify({
          message: trimmed,
          model: activeModel,
          reasoningMode,
          rolePreset,
          ...(includeAlertsContext && recentAlertsSummary
            ? { alertsSummary: recentAlertsSummary.slice(0, 2000) }
            : {}),
          ...(customFocusText ? { customFocus: customFocusText } : {}),
          history: historySnapshot,
        }),
      });

      const rawText = await res.text();
      let data: any;
      try {
        data = JSON.parse(rawText);
      } catch {
        throw new Error(`Unexpected response from chat server (HTTP ${res.status}).`);
      }

      if (!res.ok || !data.success || !data.reply) {
        throw new Error(data.message || data.error || 'Gemini failed to respond.');
      }

      if (firebaseUid && threadIdToUse) {
        await addChatMessageInFirestore(firebaseUid, threadIdToUse, {
          role: 'model',
          text: data.reply,
          model: (data.modelUsed || activeModel) as GeminiChatModel,
        });
        await updateChatThreadInFirestore(firebaseUid, threadIdToUse, {
          title:
            messages.length === 0 ? trimmed.slice(0, 60) : undefined,
          messageCount: Math.min(500, historySnapshot.length + 2),
          model: (data.modelUsed || activeModel) as GeminiChatModel,
        });
      } else {
        setMessages((prev) => [
          ...prev,
          {
            id: `mdl_${Date.now()}`,
            role: 'model',
            text: data.reply,
            model: (data.modelUsed || activeModel) as GeminiChatModel,
            createdAt: new Date().toISOString(),
          },
        ]);
      }
    } catch (err: any) {
      setErrorMsg(err?.message || 'Failed to send message.');
    } finally {
      setIsSending(false);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Left Sidebar: Saved Firestore Threads & Role Configuration */}
      <div className="lg:col-span-4 space-y-4">
        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <div className="w-8 h-8 rounded-xl bg-[#FCECF4] border border-[#F2C4DC] text-[#B52A70] flex items-center justify-center">
                <Sparkles className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-[#16161D]">Gemini AI Assistant</h3>
                <p className="text-[11px] text-[#6F6C7A]">
                  {firebaseUid ? 'Synced with Firestore' : 'Session memory active'}
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={handleNewChat}
              className="px-3 py-1.5 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-xs font-semibold flex items-center space-x-1.5 transition-colors whitespace-nowrap shrink-0"
            >
              <Plus className="w-3.5 h-3.5 text-[#F472B6]" />
              <span>New Chat</span>
            </button>
          </div>

          {/* Chatbot Role / System Instruction Selector */}
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-[#16161D]">
              Assistant Role
            </label>
            <select
              value={rolePreset}
              onChange={(e) => handleRoleChange(e.target.value as ChatRolePreset)}
              className="w-full bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl px-3 py-2 text-xs text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F]"
            >
              {Object.entries(ROLE_PRESETS).map(([key, val]) => (
                <option key={key} value={key}>
                  {val.label}
                </option>
              ))}
            </select>
            <p className="text-[11px] text-[#464451] leading-relaxed">
              {ROLE_PRESETS[rolePreset].description}
            </p>
          </div>

          {/* Model / Reasoning Speed Selector */}
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-[#16161D]">
              Model & Reasoning Mode
            </label>
            <div className="grid grid-cols-3 gap-1.5 p-1 bg-[#F2ECE2] border border-[#E5DDD0] rounded-xl text-[11px]">
              <button
                type="button"
                onClick={() => setReasoningMode('standard')}
                className={`py-2 px-2 rounded-lg flex items-center justify-center space-x-1 transition-all ${
                  reasoningMode === 'standard'
                    ? 'bg-[#16161D] text-[#FAF6F0] font-semibold shadow-2xs'
                    : 'text-[#464451] hover:text-[#16161D]'
                }`}
              >
                <Bot className="w-3.5 h-3.5" />
                <span>General</span>
              </button>
              <button
                type="button"
                onClick={() => setReasoningMode('deep')}
                className={`py-2 px-2 rounded-lg flex items-center justify-center space-x-1 transition-all ${
                  reasoningMode === 'deep'
                    ? 'bg-[#D9468F] text-[#FFFDF9] font-semibold shadow-2xs'
                    : 'text-[#464451] hover:text-[#16161D]'
                }`}
              >
                <Brain className="w-3.5 h-3.5" />
                <span>Deep</span>
              </button>
              <button
                type="button"
                onClick={() => setReasoningMode('fast')}
                className={`py-2 px-2 rounded-lg flex items-center justify-center space-x-1 transition-all ${
                  reasoningMode === 'fast'
                    ? 'bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] font-semibold shadow-2xs'
                    : 'text-[#464451] hover:text-[#16161D]'
                }`}
              >
                <Zap className="w-3.5 h-3.5" />
                <span>Fast</span>
              </button>
            </div>
            <div className="text-[11px] text-[#6F6C7A] font-mono">
              Active model:{' '}
              <span className="text-[#B52A70] font-medium">
                {activeModel}
                {reasoningMode === 'deep' ? ' (Thinking HIGH)' : ''}
              </span>
            </div>
          </div>

          {/* System Instruction Drawer */}
          <div className="space-y-2">
            <button
              type="button"
              onClick={() => setShowSystemEditor((v) => !v)}
              className="text-xs text-[#B52A70] hover:text-[#16161D] flex items-center space-x-1.5 font-medium transition-colors"
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>{showSystemEditor ? 'Hide System Instruction' : 'Customize System Instruction'}</span>
            </button>
            {showSystemEditor && (
              <textarea
                rows={4}
                value={systemInstruction}
                onChange={(e) => {
                  setRolePreset('custom');
                  setSystemInstruction(e.target.value);
                }}
                className="w-full bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl p-3 text-xs text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] resize-none"
                placeholder="Define the chatbot's persona and rules..."
              />
            )}
          </div>

          {recentAlertsSummary && (
            <label className="flex items-center space-x-2 text-xs text-[#464451] cursor-pointer pt-1">
              <input
                type="checkbox"
                checked={includeAlertsContext}
                onChange={(e) => setIncludeAlertsContext(e.target.checked)}
                className="rounded border-[#D8CEC0] bg-[#FAF6F0] text-[#D9468F] focus:ring-[#D9468F]"
              />
              <span>Attach live dashboard alerts context</span>
            </label>
          )}
        </div>

        {/* Saved Firestore Conversation Threads */}
        {firebaseUid && (
          <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-4 space-y-2.5">
            <div className="text-xs font-semibold text-[#16161D] flex items-center space-x-1.5">
              <MessageSquare className="w-3.5 h-3.5 text-[#D9468F]" />
              <span>Saved Conversations ({threads.length})</span>
            </div>
            {threads.length === 0 ? (
              <p className="text-xs text-[#6F6C7A] py-2">
                Send a message to start your first saved Firestore conversation.
              </p>
            ) : (
              <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
                {threads.map((t) => (
                  <div
                    key={t.id}
                    onClick={() => handleSelectThread(t)}
                    className={`group flex items-center justify-between px-3 py-2 rounded-xl text-xs cursor-pointer transition-colors border ${
                      activeThreadId === t.id
                        ? 'bg-[#FCECF4] border-[#D9468F]/45 text-[#16161D]'
                        : 'bg-[#FAF6F0]/80 border-[#E5DDD0] text-[#464451] hover:bg-[#F2ECE2]'
                    }`}
                  >
                    <div className="truncate pr-2">
                      <div className="font-medium truncate">{t.title}</div>
                      <div className="text-[10px] text-[#6F6C7A] font-mono">
                        {t.model} · {t.messageCount} msgs
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => handleDeleteThread(t.id, e)}
                      className="opacity-60 hover:opacity-100 text-[#6F6C7A] hover:text-[#B52A70] p-1"
                      title="Delete conversation"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Right Pane: Scrollable Multi-Turn Conversation Thread */}
      <div className="lg:col-span-8 glass-panel rounded-2xl border border-[#E5DDD0] flex flex-col h-[640px] overflow-hidden">
        {/* Chat Header */}
        <div className="px-5 py-3.5 border-b border-[#E5DDD0] bg-[#F2ECE2]/70 flex items-center justify-between gap-3">
          <div className="flex items-center space-x-2.5 min-w-0">
            <div className="w-8 h-8 rounded-xl bg-[#16161D] flex items-center justify-center text-[#FAF6F0] shrink-0">
              <Bot className="w-4 h-4 text-[#F472B6]" />
            </div>
            <div className="min-w-0">
              <div className="text-xs font-semibold text-[#16161D] truncate">
                {ROLE_PRESETS[rolePreset].label}
              </div>
              <div className="text-[11px] text-[#6F6C7A] truncate">
                Multi-turn context · {messages.length} message(s)
              </div>
            </div>
          </div>
          <span className="text-[11px] font-mono text-[#B52A70] font-medium whitespace-nowrap shrink-0">
            {activeModel}
          </span>
        </div>

        {/* Scrollable Message Thread */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4 bg-[#FFFDF9]/70">
          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center space-y-3 px-4">
              <div className="w-12 h-12 rounded-2xl bg-[#FCECF4] border border-[#F2C4DC] flex items-center justify-center text-[#B52A70]">
                <Sparkles className="w-6 h-6" />
              </div>
              <div className="space-y-1 max-w-md">
                <h4 className="font-display text-base font-semibold text-[#16161D]">
                  Start a Multi-Turn Conversation
                </h4>
                <p className="text-xs text-[#464451] leading-relaxed">
                  Ask about security alerts, incident response playbooks, or notification rules. Your conversation history is maintained across turns.
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
                {[
                  'Explain how to triage a CRITICAL webhook anomaly',
                  'Recommend quiet hours and fallback SLA rules',
                  'Summarize best practices for OTP lockout defense',
                ].map((prompt) => (
                  <button
                    key={prompt}
                    type="button"
                    onClick={() => setInputText(prompt)}
                    className="px-3 py-1.5 rounded-xl bg-[#FAF6F0] hover:bg-[#FCECF4] border border-[#E5DDD0] hover:border-[#D9468F]/40 text-[11px] text-[#16161D] transition-colors"
                  >
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex items-start gap-3 ${
                  msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'
                }`}
              >
                <div
                  className={`w-7 h-7 rounded-xl flex items-center justify-center shrink-0 mt-0.5 ${
                    msg.role === 'user'
                      ? 'bg-[#16161D] text-[#FAF6F0]'
                      : 'bg-[#FCECF4] border border-[#F2C4DC] text-[#B52A70]'
                  }`}
                >
                  {msg.role === 'user' ? (
                    <UserIcon className="w-3.5 h-3.5" />
                  ) : (
                    <Bot className="w-3.5 h-3.5" />
                  )}
                </div>

                <div
                  className={`max-w-[82%] rounded-2xl px-4 py-3 text-xs leading-relaxed whitespace-pre-wrap break-words ${
                    msg.role === 'user'
                      ? 'bg-[#16161D] text-[#FAF6F0] rounded-tr-sm shadow-xs'
                      : 'bg-[#F2ECE2]/85 border border-[#E5DDD0] text-[#16161D] rounded-tl-sm'
                  }`}
                >
                  {msg.text}
                  <div
                    className={`mt-1.5 text-[10px] font-mono ${
                      msg.role === 'user' ? 'text-[#F5CBE0]' : 'text-[#6F6C7A]'
                    }`}
                  >
                    {msg.role === 'model' && msg.model ? `${msg.model} · ` : ''}
                    {new Date(msg.createdAt).toLocaleTimeString()}
                  </div>
                </div>
              </div>
            ))
          )}

          {isSending && (
            <div className="flex items-start gap-3">
              <div className="w-7 h-7 rounded-xl bg-[#FCECF4] border border-[#F2C4DC] text-[#B52A70] flex items-center justify-center shrink-0">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              </div>
              <div className="bg-[#F2ECE2]/85 border border-[#E5DDD0] rounded-2xl rounded-tl-sm px-4 py-3 text-xs text-[#464451]">
                Thinking with {activeModel}...
              </div>
            </div>
          )}

          <div ref={threadEndRef} />
        </div>

        {/* Error Banner */}
        {errorMsg && (
          <div className="mx-4 mb-2 p-3 rounded-xl bg-[#FDF2F6] border border-[#D9468F]/40 text-[#88134A] text-xs flex items-start space-x-2">
            <AlertCircle className="w-4 h-4 text-[#D9468F] shrink-0 mt-0.5" />
            <span className="flex-1 break-words">{errorMsg}</span>
          </div>
        )}

        {/* Composer */}
        <form
          onSubmit={handleSendMessage}
          className="p-4 border-t border-[#E5DDD0] bg-[#FAF6F0] flex items-end gap-2.5"
        >
          <textarea
            rows={2}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                void handleSendMessage();
              }
            }}
            placeholder="Ask Gemini a follow-up question... (Enter to send, Shift+Enter for new line)"
            className="flex-1 bg-[#FFFDF9] border border-[#D8CEC0] rounded-xl px-4 py-2.5 text-xs text-[#16161D] placeholder-[#8A8794] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] resize-none"
          />
          <button
            type="submit"
            disabled={isSending || !inputText.trim()}
            className="px-4 py-3 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] disabled:opacity-40 disabled:cursor-not-allowed text-[#FFFDF9] text-xs font-semibold flex items-center space-x-1.5 transition-all whitespace-nowrap shrink-0 shadow-xs"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Send</span>
          </button>
        </form>
      </div>
    </div>
  );
}
