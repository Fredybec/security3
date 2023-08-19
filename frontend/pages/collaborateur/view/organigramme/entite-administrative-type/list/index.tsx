import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import EntiteAdministrativeTypesList from 'app/component/collaborateur/view/organigramme/entite-administrative-type/list/entite-administrative-type-list-collaborateur.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const EntiteAdministrativeTypes: NextPageWithLayout = () => {
    return <EntiteAdministrativeTypesList />
}

EntiteAdministrativeTypes.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default EntiteAdministrativeTypes;
