import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import RoleUtilisateursList from 'app/component/admin/view/referentiel-partage/role-utilisateur/list/role-utilisateur-list-admin.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const RoleUtilisateurs: NextPageWithLayout = () => {
    return <RoleUtilisateursList />
}

RoleUtilisateurs.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default RoleUtilisateurs;
