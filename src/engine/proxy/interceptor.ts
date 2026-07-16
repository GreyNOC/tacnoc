/**
 * Interceptor — holds requests/responses when interception is enabled and
 * resolves them when the UI (or a test) decides to forward/edit/drop.
 *
 * When interception is disabled, holds resolve immediately with "forward" so
 * traffic flows freely. Toggling interception OFF releases anything currently
 * held (auto-forward) so nothing hangs.
 */

import { EventEmitter } from 'node:events';
import type {
  InterceptState,
  InterceptedRequestView,
  InterceptedResponseView,
  RequestDecision,
  ResponseDecision,
} from '../../shared/intercept.js';

interface PendingRequest {
  view: InterceptedRequestView;
  resolve: (decision: RequestDecision) => void;
}
interface PendingResponse {
  view: InterceptedResponseView;
  resolve: (decision: ResponseDecision) => void;
}

export class Interceptor extends EventEmitter {
  private state: InterceptState = { interceptRequests: false, interceptResponses: false };
  private readonly pendingRequests = new Map<string, PendingRequest>();
  private readonly pendingResponses = new Map<string, PendingResponse>();

  getState(): InterceptState {
    return { ...this.state };
  }

  setState(partial: Partial<InterceptState>): void {
    const next = { ...this.state, ...partial };
    const turningOffReq = this.state.interceptRequests && !next.interceptRequests;
    const turningOffRes = this.state.interceptResponses && !next.interceptResponses;
    this.state = next;
    if (turningOffReq) this.releaseAllRequests();
    if (turningOffRes) this.releaseAllResponses();
    this.emit('state', this.getState());
  }

  /** Hold a request for a decision, or auto-forward when interception is off. */
  holdRequest(view: InterceptedRequestView): Promise<RequestDecision> {
    if (!this.state.interceptRequests) return Promise.resolve({ action: 'forward' });
    return new Promise((resolve) => {
      this.pendingRequests.set(view.id, { view, resolve });
      this.emit('request-held', view);
      this.emit('pending-changed');
    });
  }

  resolveRequest(id: string, decision: RequestDecision): boolean {
    const pending = this.pendingRequests.get(id);
    if (!pending) return false;
    this.pendingRequests.delete(id);
    pending.resolve(decision);
    this.emit('request-resolved', id);
    this.emit('pending-changed');
    return true;
  }

  holdResponse(view: InterceptedResponseView): Promise<ResponseDecision> {
    if (!this.state.interceptResponses) return Promise.resolve({ action: 'forward' });
    return new Promise((resolve) => {
      this.pendingResponses.set(view.id, { view, resolve });
      this.emit('response-held', view);
      this.emit('pending-changed');
    });
  }

  resolveResponse(id: string, decision: ResponseDecision): boolean {
    const pending = this.pendingResponses.get(id);
    if (!pending) return false;
    this.pendingResponses.delete(id);
    pending.resolve(decision);
    this.emit('response-resolved', id);
    this.emit('pending-changed');
    return true;
  }

  listPendingRequests(): InterceptedRequestView[] {
    return [...this.pendingRequests.values()].map((p) => p.view);
  }
  listPendingResponses(): InterceptedResponseView[] {
    return [...this.pendingResponses.values()].map((p) => p.view);
  }

  /** Release everything as forward — used on shutdown/emergency stop. */
  releaseAll(): void {
    this.releaseAllRequests();
    this.releaseAllResponses();
  }

  private releaseAllRequests(): void {
    for (const [id, p] of this.pendingRequests) {
      this.pendingRequests.delete(id);
      p.resolve({ action: 'forward' });
    }
    this.emit('pending-changed');
  }
  private releaseAllResponses(): void {
    for (const [id, p] of this.pendingResponses) {
      this.pendingResponses.delete(id);
      p.resolve({ action: 'forward' });
    }
    this.emit('pending-changed');
  }
}
