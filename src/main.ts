import axios from 'axios';
import { BufferConverter, DeviceProvider, OauthClient, ScryptedDeviceBase, ScryptedInterface, ScryptedMimeTypes, Setting, Settings } from '@scrypted/sdk';
import qs from 'query-string';
import { GcmRtcManager, GcmRtcConnection } from './legacy';
import { Duplex } from 'stream';
import net from 'net';
import HttpProxy from 'http-proxy';
import { Server, createServer } from 'http';
import Url from 'url';
import {once} from 'events';
import sdk from '@scrypted/sdk';

const {deviceManager} = sdk;

export const DEFAULT_SENDER_ID = '827888101440';

export async function createDefaultRtcManager(): Promise<GcmRtcManager> {
    const manager = await GcmRtcManager.start({
        // Scrypted
        '827888101440': '',
    },
        {
            iceServers: [
                {
                    urls: ["turn:turn0.clockworkmod.com", "turn:n0.clockworkmod.com", "turn:n1.clockworkmod.com"],
                    username: "foo",
                    credential: "bar",
                },
            ],
        });

    return manager;
}

async function whitelist(localUrl: string, ttl: number): Promise<Buffer|string> {
    const local = Url.parse(localUrl);
    const token_info = localStorage.getItem('token_info');
    const q = qs.stringify({
        scope: local.path,
        ttl,
    })
    const scope = await axios(`https://home.scrypted.app/_punch/scope?${q}`, {
        headers: {
            Authorization: `Bearer ${token_info}`
        },
    })

    const {userToken, userTokenSignature} = scope.data;
    const tokens = qs.stringify({
        user_token: userToken,
        user_token_signature: userTokenSignature
    })

    const url = `https://home.scrypted.app${local.path}?${tokens}`;
    return url;
}

class ScryptedCloud extends ScryptedDeviceBase implements OauthClient, Settings, BufferConverter {
    manager: GcmRtcManager;
    server: Server;
    proxy: HttpProxy;

    constructor() {
        super();

        this.initialize();

        this.fromMimeType = `${ScryptedMimeTypes.LocalUrl};${ScryptedMimeTypes.AcceptUrlParameter}=true`;
        this.toMimeType = ScryptedMimeTypes.Url;
    }

    async convert(data: Buffer|string, fromMimeType: string): Promise<Buffer|string> {
        return whitelist(data.toString(), 10 * 365 * 24 * 60 * 60 * 1000);
    }

    async getSettings(): Promise<Setting[]> {
        return [
            {
                title: 'Refresh Token',
                value: this.storage.getItem('token_info'),
                description: 'Authorization token used by Scrypted Cloud.',
                readonly: true,
            }
        ]
    }
    putSetting(key: string, value: string | number | boolean): void {
    }

    async getOauthUrl(): Promise<string> {
        const args = qs.stringify({
            registration_id: this.manager.registrationId,
            sender_id: DEFAULT_SENDER_ID,
        })
        return `https://home.scrypted.app/_punch/login?${args}`
    }

    onOauthCallback(callbackUrl: string): void {
    }

    async initialize() {
        this.server = createServer((req, res) => {
            const url = Url.parse(req.url);
            if (url.path.startsWith('/web/oauth/callback') && url.query) {
                const query = qs.parse(url.query);
                if (!query.callback_url && query.token_info && query.user_info) {
                    localStorage.setItem('token_info', query.token_info as string)
                    res.setHeader('Location', 'https://home.scrypted.app/endpoint/@scrypted/core/public/');
                    res.writeHead(302);
                    res.end();
                    return;
                }
            }
            else if (url.path === '/web/') {
                res.setHeader('Location', 'https://home.scrypted.app/endpoint/@scrypted/core/public/');
                res.writeHead(302);
                res.end();
                return;
            }
            else if (url.path === '/web/component/home/endpoint') {
                this.proxy.web(req, res, {
                    target: 'https://localhost:9443/endpoint/@scrypted/google-home/public/',
                    ignorePath: true,
                    secure: false,
                });
                return;
            }

            if (req.headers.upgrade == 'websocket')
                this.proxy.ws(req, req.socket, { target: 'https://localhost:9443', ws: true, secure: false });
            else
                this.proxy.web(req, res);
        }).listen(0);
        await once(this.server, 'listening');
        const port = (this.server.address() as any).port;

        this.proxy = HttpProxy.createProxy({
            target: `https://localhost:9443`,
            secure: false,
        });
        this.proxy.on('error', () => {})

        this.manager = await createDefaultRtcManager();
        this.manager.listen("http://localhost", (conn: GcmRtcConnection) => {
            conn.on('socket', (command: string, socket: Duplex) => {
                const local = net.connect({
                    port,
                    host: 'localhost',
                })

                local.pipe(socket).pipe(local);
            });
        })
        
        const token_info = localStorage.getItem('token_info');
        if (token_info) {
            const q = qs.stringify({
                fcm_registration_id: this.manager.registrationId,
                sender_id: DEFAULT_SENDER_ID,
            })
            const register = await axios(`https://home.scrypted.app/_punch/register?${q}`, {
                headers: {
                    Authorization: `Bearer ${token_info}`
                },
            })
            console.log(register);
        }
    }
}

export default new ScryptedCloud();
