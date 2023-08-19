import React, {useRef, useState} from 'react';

import styles from './styles.module.scss';
import {useRouter} from 'next/router';
import {InputText} from 'primereact/inputtext';
import {Password} from 'primereact/password';
import {Checkbox} from 'primereact/checkbox';
import {Button} from 'primereact/button';
import {Toast} from 'primereact/toast';
import {AuthService} from 'app/zynerator/security/Auth.service';
import {MessageService} from '/app/zynerator/service/MessageService';

const AuthContainer: React.FC = ({}) => {

    const [username, setUsername] = useState("");
    const [password, setPassword] = useState('');
    const [checked, setChecked] = useState(false);
    const router = useRouter();
    const [userService, setUserService] = useState(new AuthService());
    const toast = useRef<Toast>();

    const handleAuthFormClick = () => {
        userService.signIn(username, password).then(data => {
            const jwt = data.headers['authorization'];
            if (jwt) {
                userService.saveToken(jwt)
                router.push("/dashboard")
            }else{
                MessageService.showError(toast,'Probléme de connexion');
            }
        }).catch(() => {
            MessageService.showError(toast,'Vos identifiants sont incorrects');
        })
    }

    return (
        <div className={styles.authForm}>
            <h2 className="mb-5">Saisissez vos identifiants</h2>
            <span className="mb-5">Votre mail et mot de passe seront utilisés pour vous connecter ou alors pour vous inviter à créer un compte si vous n'en avez pas encore.</span>

            <div>
                <label htmlFor="email" className="block text-900 text-base font-medium mb-2">
                    Email
                </label>
                <InputText id="email" type="text" placeholder="Saisissez votre email"
                           onChange={(e) => setUsername(e.target.value)} className="w-full mb-5"
                           style={{padding: '1rem'}}/>

                <label htmlFor="password" className="block text-900 font-medium text-base mb-2">
                    Mot de passe
                </label>
                <Password inputId="password" value={password} onChange={(e) => setPassword(e.target.value)}
                          feedback={false} placeholder="Saisissez votre email" toggleMask className="w-full mb-5"
                          inputClassName="w-full p-3 md:w-30rem"></Password>

                <div className="flex align-items-center justify-content-between mb-5 gap-5">
                    <div className="flex align-items-center">
                        <Checkbox inputId="rememberMe" checked={checked}
                                  onChange={(e) => setChecked(e.checked ?? false)} className="mr-2"></Checkbox>
                        <label htmlFor="rememberMe">Remember me</label>
                    </div>
                </div>
                <Button label="Se connecter" className="w-full p-3 text-large" onClick={handleAuthFormClick}></Button>
            </div>
            <Toast ref={toast}/>
        </div>
    );
};

export default AuthContainer;
