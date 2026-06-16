document.addEventListener('alpine:init', () => {
    Alpine.data('confirmModal', () => ({
        isOpen: false,
        title: '',
        message: '',
        confirmText: 'Confirm',
        actionUrl: '',
        undoUrl: '',
        actionMethod: 'POST',
        action: '',
        target: '',
        currentState: '',
        reason: '',
        ticketId: '',
        ttl: 3600,
        isDanger: false,
        confirmDisabled: true,

        open(config) {
            this.action = config.action || 'block';
            this.target = config.ip || config.ja4 || config.target || '';
            this.currentState = config.currentState || 'active';

            const labels = {
                'block':     {title: 'Block IP',         url: `/api/v1/bans/${this.target}`},
                'tarpit':    {title: 'Tarpit IP',        url: `/api/v1/actions/${this.target}/tarpit`},
                'allow':     {title: 'Allowlist IP',     url: `/api/v1/allowlist/${this.target}`},
                'watchlist': {title: 'Add to Watchlist', url: `/api/v1/watchlist/${this.target}`},
            };
            const label = labels[this.action] || labels.block;
            this.title = label.title;
            this.actionUrl = label.url;
            this.undoUrl = this.actionUrl;
            this.confirmText = this.title;
            this.isDanger = (this.action === 'block' || this.action === 'allow');
            this.reason = '';
            this.ticketId = '';
            this.ttl = config.ttl || 3600;
            this.confirmDisabled = true;
            this.isOpen = true;
        },

        close() {
            this.isOpen = false;
        },

        onReasonInput() {
            this.confirmDisabled = this.reason.trim().length < 10;
        },

        async submit() {
            if (this.reason.trim().length < 10) {
                return;
            }

            const body = {reason: this.reason.trim(), ttl: this.ttl};
            if (this.ticketId.trim()) {
                body.ticket_id = this.ticketId.trim();
            }

            try {
                const response = await fetch(this.actionUrl, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(body),
                });

                if (response.ok) {
                    this.close();
                    window.dispatchEvent(new CustomEvent('action-completed', {
                        detail: {
                            message: `${this.title} applied to ${this.target}`,
                            undoUrl: this.undoUrl,
                            method: 'DELETE',
                        },
                    }));
                } else {
                    const err = await response.json();
                    window.dispatchEvent(new CustomEvent('action-error', {
                        detail: {message: err.detail || 'Action failed'},
                    }));
                }
            } catch (e) {
                console.error('confirmModal submit error:', e);
                window.dispatchEvent(new CustomEvent('action-error', {
                    detail: {message: 'Network error executing request.'},
                }));
            }
        },
    }));
});

window.ConfirmModal = {
    open(config) {
        const modalEl = document.querySelector('[x-data="confirmModal"]');
        if (modalEl && modalEl.__x) {
            modalEl.__x.$data.open(config);
        }
    },
};
