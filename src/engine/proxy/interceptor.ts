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
    // FORWARD here, unlike the stop paths. Switching interception off means
    // "stop holding my traffic and let it through" — dropping the queue would
    // break the pages the operator is trying to resume browsing.
    if (turningOffReq) this.releaseAllRequests('forward');
    if (turningOffRes) this.releaseAllResponses('forward');
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

  /**
   * Release every held message so nothing is left waiting on a decision.
   *
   * The action is explicit and the callers choose it, because the two callers
   * mean opposite things. Emergency stop and proxy shutdown mean **drop**: a
   * held request has not been sent yet, and resolving it as `forward` sends it —
   * so releasing on `forward` made the emergency stop deliver every queued
   * request to the target, which is the precise opposite of what the control
   * says it does and of what an operator hits it for. Dropping loses nothing
   * that was not already the operator's to lose: the request was still theirs to
   * cancel while it sat in the queue.
   *
   * @param action what to do with everything still held. Defaults to `drop`, so
   *   a future caller that forgets to think about it fails safe.
   */
  releaseAll(action: 'forward' | 'drop' = 'drop'): void {
    this.releaseAllRequests(action);
    this.releaseAllResponses(action);
  }

  private releaseAllRequests(action: 'forward' | 'drop'): void {
    for (const [id, p] of this.pendingRequests) {
      this.pendingRequests.delete(id);
      p.resolve({ action });
    }
    this.emit('pending-changed');
  }
  private releaseAllResponses(action: 'forward' | 'drop'): void {
    for (const [id, p] of this.pendingResponses) {
      this.pendingResponses.delete(id);
      p.resolve({ action });
    }
    this.emit('pending-changed');
  }
}
