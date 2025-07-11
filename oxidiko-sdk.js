// Oxidiko Web Vault JavaScript SDK (Secure postMessage flow)
class OxidikoAuth {
    constructor(options = {}) {
        this.baseUrl = options.baseUrl || 'https://www.oxidiko.com'
        this.apiKey = options.apiKey || null
        this.popupWidth = options.popupWidth || 500
        this.popupHeight = options.popupHeight || 700
    }

    authenticate(fields, redirectUrl = null) {
      return new Promise((resolve, reject) => {
        const fieldsParam = Array.isArray(fields) ? fields.join(',') : fields
        const redirect = redirectUrl || window.location.href

        // Open popup
        const authUrl = `${this.baseUrl}/login`
        const left = (screen.width - this.popupWidth) / 2
        const top = (screen.height - this.popupHeight) / 2
        const popup = window.open(
          authUrl,
          'oxidiko-auth',
          `width=${this.popupWidth},height=${this.popupHeight},left=${left},top=${top},scrollbars=yes,resizable=yes`
        )
        if (!popup) {
          reject(new Error('Failed to open popup. Please allow popups for this site.'))
          return
        }

        let ready = false
        let checkClosedInterval

        // Listen for messages from popup
        const messageListener = (event) => {
          const authOrigin = new URL(this.baseUrl).origin
          const currentOrigin = window.location.origin
          if (event.origin !== authOrigin && event.origin !== currentOrigin) return

          // Wait for popup to signal it's ready
          if (event.data && event.data.oxidikoReady && !ready) {
            ready = true
            // Send data via postMessage
            popup.postMessage(
              {
                api_key: this.apiKey,
                fields: fieldsParam,
                redirect
              },
              authOrigin
            )
            return
          }

          if (event.data.type === 'OXID_AUTH_SUCCESS') {
            cleanup()
            resolve({
              success: true,
              token: event.data.token,
              userData: event.data.userData || null
            })
          } else if (event.data.type === 'OXID_AUTH_ERROR') {
            cleanup()
            reject(new Error(event.data.error || 'Authentication failed'))
          }
        }

        const cleanup = () => {
          window.removeEventListener('message', messageListener)
          if (popup && !popup.closed) popup.close()
          if (checkClosedInterval) clearInterval(checkClosedInterval)
        }

        window.addEventListener('message', messageListener)

        checkClosedInterval = setInterval(() => {
          if (popup.closed) {
            cleanup()
            reject(new Error('Authentication was cancelled by user'))
          }
        }, 1000)

        setTimeout(() => {
          if (!popup.closed) {
            cleanup()
            reject(new Error('Authentication timeout'))
          }
        }, 300000)
      })
    }

    async verifyToken(token) {
        try {
            const payload = JSON.parse(atob(token.split('.')[1]))
            if (payload.exp && payload.exp < Date.now() / 1000) {
                throw new Error('Token has expired')
            }
            return payload
        } catch (error) {
            throw new Error('Invalid token format')
        }
    }
}
