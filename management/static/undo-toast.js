document.addEventListener('alpine:init', () => {
    Alpine.data('undoToast', () => ({
        visible: false,
        message: '',
        undoUrl: '',
        undoMethod: 'DELETE',
        countdown: 30,
        timer: null,

        init() {
            window.addEventListener('action-completed', (e) => {
                this.show(e.detail.message, e.detail.undoUrl, e.detail.method || 'DELETE');
            });

            window.addEventListener('action-error', (e) => {
                const notifications = document.getElementById('notification-area');
                if (notifications) {
                    const div = document.createElement('div');
                    div.className = 'bg-red-900/80 text-red-200 px-4 py-2 rounded text-sm';
                    div.textContent = e.detail.message;
                    notifications.appendChild(div);
                    setTimeout(() => div.remove(), 5000);
                }
            });
        },

        show(msg, url, method) {
            this.message = msg;
            this.undoUrl = url;
            this.undoMethod = method || 'DELETE';
            this.countdown = 30;
            this.visible = true;

            if (this.timer) clearInterval(this.timer);
            this.timer = setInterval(() => {
                this.countdown--;
                if (this.countdown <= 0) this.hide();
            }, 1000);
        },

        hide() {
            this.visible = false;
            if (this.timer) {
                clearInterval(this.timer);
                this.timer = null;
            }
        },

        async undo() {
            try {
                const response = await fetch(this.undoUrl, {method: this.undoMethod});
                if (response.ok) {
                    this.hide();
                    const notifications = document.getElementById('notification-area');
                    if (notifications) {
                        const div = document.createElement('div');
                        div.className = 'bg-green-900/80 text-green-200 px-4 py-2 rounded text-sm';
                        div.textContent = 'Action reverted successfully.';
                        notifications.appendChild(div);
                        setTimeout(() => div.remove(), 5000);
                    }
                    document.body.dispatchEvent(new CustomEvent('ban-updated'));
                } else {
                    const notifications = document.getElementById('notification-area');
                    if (notifications) {
                        const div = document.createElement('div');
                        div.className = 'bg-red-900/80 text-red-200 px-4 py-2 rounded text-sm';
                        div.textContent = 'Failed to undo action.';
                        notifications.appendChild(div);
                        setTimeout(() => div.remove(), 5000);
                    }
                }
            } catch (e) {
                console.error('undo error:', e);
            }
        },
    }));
});
