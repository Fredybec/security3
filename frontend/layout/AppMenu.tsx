/* eslint-disable @next/next/no-img-element */

import AppMenuitem from '/layout/AppMenuitem';
import {MenuProvider} from '/layout/context/menucontext';
import {AppMenuItem} from '/types/types';
import {AuthService} from 'app/zynerator/security/Auth.service';
import React, {useEffect, useState} from 'react';


const AppMenu = () => {
    const [model,setModel] = useState<AppMenuItem[]>([] as AppMenuItem[]);
    const authService = new AuthService();
        const modelAdmin: AppMenuItem[] = [
        {
            label: 'Home',
            items: [{label: 'Dashboard', icon: 'pi pi-fw pi-home', to: '/dashboard'}]
        },


        {
            label: 'Pages',
            icon: 'pi pi-fw pi-briefcase',
            to: '',
            items: [

                {
                    label: 'Auth',
                    icon: 'pi pi-fw pi-user',
                    items: [
                        {
                            label: 'Error',
                            icon: 'pi pi-fw pi-times-circle',
                            to: '/auth/error'
                        },
                        {
                            label: 'Access Denied',
                            icon: 'pi pi-fw pi-lock',
                            to: '/auth/access'
                        }
                    ]
                },
                {
                    label: 'Referentiel Document',
                    icon: 'pi pi-fw pi-plus-circle',
                    items: [
                      {
                      label: 'Liste document type',
                     to: '/admin/view/referentiel-doc/document-type/list'
                      },
                      {
                      label: 'Liste document categorie',
                     to: '/admin/view/referentiel-doc/document-categorie/list'
                      },
                      {
                      label: 'Liste document categorie model',
                     to: '/admin/view/referentiel-doc/document-categorie-model/list'
                      },
                      {
                      label: 'Liste document state',
                     to: '/admin/view/referentiel-doc/document-state/list'
                      },
                      {
                      label: 'Liste tag',
                     to: '/admin/view/referentiel-doc/tag/list'
                      },
                      {
                      label: 'Liste document categorie index',
                     to: '/admin/view/referentiel-doc/document-categorie-index/list'
                      },
                      {
                      label: 'Liste document categorie index rule',
                     to: '/admin/view/referentiel-doc/document-categorie-index-rule/list'
                      },
                      {
                      label: 'Liste index element',
                     to: '/admin/view/referentiel-doc/index-element/list'
                      },
                    ]
                    },
                {
                    label: 'Document Management',
                    icon: 'pi pi-fw pi-plus-circle',
                    items: [
                      {
                      label: 'Liste document',
                     to: '/admin/view/doc/document/list'
                      },
                    ]
                    },
                {
                    label: 'Organigramme Management',
                    icon: 'pi pi-fw pi-plus-circle',
                    items: [
                      {
                      label: 'Liste gender',
                     to: '/admin/view/organigramme/gender/list'
                      },
                      {
                      label: 'Liste entite administrative type',
                     to: '/admin/view/organigramme/entite-administrative-type/list'
                      },
                      {
                      label: 'Liste utilisateur',
                     to: '/admin/view/organigramme/utilisateur/list'
                      },
                      {
                      label: 'Liste entite administrative',
                     to: '/admin/view/organigramme/entite-administrative/list'
                      },
                    ]
                    },
                {
                    label: 'Referentiel Partage',
                    icon: 'pi pi-fw pi-plus-circle',
                    items: [
                      {
                      label: 'Liste role utilisateur',
                     to: '/admin/view/referentiel-partage/role-utilisateur/list'
                      },
                      {
                      label: 'Liste access share',
                     to: '/admin/view/referentiel-partage/access-share/list'
                      },
                      {
                      label: 'Liste etat utilisateur',
                     to: '/admin/view/referentiel-partage/etat-utilisateur/list'
                      },
                      {
                      label: 'Liste groupe',
                     to: '/admin/view/referentiel-partage/groupe/list'
                      },
                    ]
                    },
            ]
        },

    ];
    const modelCollaborateur: AppMenuItem[] = [
        {
            label: 'Home',
            items: [{label: 'Dashboard', icon: 'pi pi-fw pi-home', to: '/dashboard'}]
        },


        {
            label: 'Pages',
            icon: 'pi pi-fw pi-briefcase',
            to: '',
            items: [

                {
                    label: 'Auth',
                    icon: 'pi pi-fw pi-user',
                    items: [
                        {
                            label: 'Error',
                            icon: 'pi pi-fw pi-times-circle',
                            to: '/auth/error'
                        },
                        {
                            label: 'Access Denied',
                            icon: 'pi pi-fw pi-lock',
                            to: '/auth/access'
                        }
                    ]
                },
                {
                    label: 'Referentiel Document',
                    icon: 'pi pi-fw pi-plus-circle',
                    items: [
                      {
                      label: 'Liste document type',
                     to: '/collaborateur/view/referentiel-doc/document-type/list'
                      },
                      {
                      label: 'Liste document state',
                     to: '/collaborateur/view/referentiel-doc/document-state/list'
                      },
                      {
                      label: 'Liste tag',
                     to: '/collaborateur/view/referentiel-doc/tag/list'
                      },
                    ]
                    },
                {
                    label: 'Document Management',
                    icon: 'pi pi-fw pi-plus-circle',
                    items: [
                      {
                      label: 'Liste document',
                     to: '/collaborateur/view/doc/document/list'
                      },
                    ]
                    },
                {
                    label: 'Organigramme Management',
                    icon: 'pi pi-fw pi-plus-circle',
                    items: [
                      {
                      label: 'Liste gender',
                     to: '/collaborateur/view/organigramme/gender/list'
                      },
                      {
                      label: 'Liste entite administrative type',
                     to: '/collaborateur/view/organigramme/entite-administrative-type/list'
                      },
                      {
                      label: 'Liste utilisateur',
                     to: '/collaborateur/view/organigramme/utilisateur/list'
                      },
                      {
                      label: 'Liste entite administrative',
                     to: '/collaborateur/view/organigramme/entite-administrative/list'
                      },
                    ]
                    },
                {
                    label: 'Referentiel Partage',
                    icon: 'pi pi-fw pi-plus-circle',
                    items: [
                      {
                      label: 'Liste role utilisateur',
                     to: '/collaborateur/view/referentiel-partage/role-utilisateur/list'
                      },
                      {
                      label: 'Liste access share',
                     to: '/collaborateur/view/referentiel-partage/access-share/list'
                      },
                      {
                      label: 'Liste etat utilisateur',
                     to: '/collaborateur/view/referentiel-partage/etat-utilisateur/list'
                      },
                      {
                      label: 'Liste groupe',
                     to: '/collaborateur/view/referentiel-partage/groupe/list'
                      },
                    ]
                    },
            ]
        },

    ];

    useEffect(()=>{
        console.log("hnaaaa")
        const roleConnectedUser = authService.getRoleConnectedUser();
        if(roleConnectedUser === 'ROLE_ADMIN'){
            setModel(modelAdmin)
        }
        if(roleConnectedUser === 'ROLE_COLLABORATEUR'){
            setModel(modelCollaborateur)
        }
    },[])

    return (
        <MenuProvider>
            <ul className="layout-menu">
                {model.map((item, i) => {
                    return !item?.seperator ? <AppMenuitem item={item} root={true} index={i} key={item.label}/> :
                        <li className="menu-separator"></li>;
                })}


            </ul>
        </MenuProvider>
    );
};


export default AppMenu;
