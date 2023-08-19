import { NextPageWithLayout } from 'next';
import AuthContainer from 'app/component/auth/Auth.container';
import { ReactNode } from 'react';
import AuthLayout from 'layout/AuthLayout';

const Auth : NextPageWithLayout = () => {
    return <AuthContainer />
}


Auth.getLayout = function getLayout(page: ReactNode) {
    return (
        <AuthLayout>
            {page}
        </AuthLayout>
    )
}

export default Auth;
