import {NextPageWithLayout} from 'next';
import {ReactNode} from 'react';

import EtatUtilisateursList from 'app/component/collaborateur/view/referentiel-partage/etat-utilisateur/list/etat-utilisateur-list-collaborateur.component';
import Layout from 'layout/layout';
import AuthGuard from 'app/component/auth/auth-guard.component';

const EtatUtilisateurs: NextPageWithLayout = () => {
    return <EtatUtilisateursList />
}

EtatUtilisateurs.getLayout = function getLayout(page: ReactNode) {
    return (
    <AuthGuard>
        <Layout>
            {page}
        </Layout>
    </AuthGuard>
    )
}

export default EtatUtilisateurs;
