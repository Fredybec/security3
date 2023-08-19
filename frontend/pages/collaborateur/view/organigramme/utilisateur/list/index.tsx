import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import UtilisateursList from 'app/component/collaborateur/view/organigramme/utilisateur/list/utilisateur-list-collaborateur.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const Utilisateurs: NextPageWithLayout = () => {
    return <UtilisateursList />
}

Utilisateurs.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default Utilisateurs;
