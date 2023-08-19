import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import RoleUtilisateursList from 'app/component/collaborateur/view/referentiel-partage/role-utilisateur/list/role-utilisateur-list-collaborateur.component';
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
