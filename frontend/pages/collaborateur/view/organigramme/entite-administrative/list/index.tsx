import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import EntiteAdministrativesList from 'app/component/collaborateur/view/organigramme/entite-administrative/list/entite-administrative-list-collaborateur.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const EntiteAdministratives: NextPageWithLayout = () => {
    return <EntiteAdministrativesList />
}

EntiteAdministratives.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default EntiteAdministratives;
