import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import AccessSharesList from 'app/component/admin/view/referentiel-partage/access-share/list/access-share-list-admin.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const AccessShares: NextPageWithLayout = () => {
    return <AccessSharesList />
}

AccessShares.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default AccessShares;
