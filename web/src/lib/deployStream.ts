import type { DeployEvent, DeployLogEvent } from './api';

/**
 * Bus mínimo para el flujo de despliegue.
 *
 * POR QUÉ NO ES ESTADO DE REACT
 * -----------------------------
 * Una build verbosa (`npm ci` de un monorepo, `docker build` con BuildKit)
 * escupe miles de líneas por segundo. Si cada línea entrase por `useState` en
 * `App`, cada línea sería un render del árbol entero.
 *
 * Y no, el batching automático de React 19 no lo arregla: agrupa las
 * actualizaciones que ocurren dentro de la MISMA tarea, y cada mensaje de
 * WebSocket llega en su propio macrotask. Mil mensajes son mil tareas, o sea
 * mil renders.
 *
 * Así que las líneas no tocan el estado. `App` las publica aquí, el visor las
 * acumula en un ref y vuelca una sola vez por frame de animación. El coste pasa
 * de O(líneas) renders a O(frames): 60 por segundo como mucho, lleguen 100
 * líneas o 10.000.
 */

type Handler<T> = (payload: T) => void;

class DeployStream {
  private logHandlers = new Set<Handler<DeployLogEvent>>();
  private eventHandlers = new Set<Handler<DeployEvent>>();

  onLog(handler: Handler<DeployLogEvent>): () => void {
    this.logHandlers.add(handler);
    return () => { this.logHandlers.delete(handler); };
  }

  onEvent(handler: Handler<DeployEvent>): () => void {
    this.eventHandlers.add(handler);
    return () => { this.eventHandlers.delete(handler); };
  }

  emitLog(payload: DeployLogEvent): void {
    // Un suscriptor que lanza no puede dejar sin línea a los demás ni tumbar el
    // manejador del WebSocket, que dejaría de reconectar.
    for (const handler of this.logHandlers) {
      try { handler(payload); } catch { /* el visor no puede romper el socket */ }
    }
  }

  emitEvent(payload: DeployEvent): void {
    for (const handler of this.eventHandlers) {
      try { handler(payload); } catch { /* ídem */ }
    }
  }
}

export const deployStream = new DeployStream();
