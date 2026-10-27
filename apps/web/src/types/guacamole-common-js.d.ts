// Types for guacamole-common-js, which ships none: only what Owlery uses, so nothing is promised that was not tried.
//

declare module 'guacamole-common-js' {
  namespace Guacamole {
    class Tunnel {
      static readonly State: {
        CONNECTING: number
        OPEN: number
        CLOSED: number
        UNSTABLE: number
      }
      onerror: ((status: Status) => void) | null
      onstatechange: ((state: number) => void) | null
    }

    class WebSocketTunnel extends Tunnel {
      constructor(url: string)
    }

    class Status {
      code: number
      message?: string
    }

    class Display {
      getElement(): HTMLElement
      getWidth(): number
      getHeight(): number
      scale(factor: number): void
      onresize: ((width: number, height: number) => void) | null
    }

    class Client {
      constructor(tunnel: Tunnel)
      connect(data?: string): void
      disconnect(): void
      getDisplay(): Display
      sendSize(width: number, height: number): void
      sendKeyEvent(pressed: number, keysym: number): void
      sendMouseState(state: Mouse.State): void
      onerror: ((status: Status) => void) | null
      onstatechange: ((state: number) => void) | null
      onname: ((name: string) => void) | null
    }

    namespace Mouse {
      class State {
        x: number
        y: number
        left: boolean
        middle: boolean
        right: boolean
        up: boolean
        down: boolean
      }
    }

    class Mouse {
      constructor(element: HTMLElement)
      onmousedown: ((state: Mouse.State) => void) | null
      onmouseup: ((state: Mouse.State) => void) | null
      onmousemove: ((state: Mouse.State) => void) | null
      onmouseout: (() => void) | null
    }

    class Keyboard {
      constructor(element: HTMLElement | Document)
      onkeydown: ((keysym: number) => boolean | void) | null
      onkeyup: ((keysym: number) => void) | null
      reset(): void
    }
  }

  export default Guacamole
}
