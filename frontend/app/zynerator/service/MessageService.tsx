export const MessageService = {

    showToast: (toastRef, options) => {
        if (toastRef && options) {
            toastRef.current?.show(options);
        }
    },

    showSuccess: (toastRef, message) => {
        let options = {severity: 'success', summary: 'Successful', detail: message, life: 3000};
        toastRef.current?.show(options);
    },

    showError: (toastRef, message) => {
        let options = {severity: 'error', summary: 'Erreur', detail: message, life: 3000};
        toastRef.current?.show(options);
    }
};
