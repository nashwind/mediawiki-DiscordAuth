<?php

namespace DiscordAuth\AuthenticationProvider;

use Wohali\OAuth2\Client\Provider\Discord;
use MediaWiki\MediaWikiServices;
use MediaWiki\User\UserIdentity;
use WSOAuth\AuthenticationProvider\AuthProvider;

class DiscordAuth extends AuthProvider {

    const SOURCE = 'source';
    const DISCORD = 'discord';

    /**
     * @var Discord
     */
    private $provider;
    private $collectEmail;
    private $config;

    /**
     * @inheritDoc
     */
    public function __construct( string $clientId, string $clientSecret, ?string $authUri, ?string $redirectUri, array $extensionData = [] ) {
        $this->provider = new Discord([
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $redirectUri
        ]);
        $this->config = MediaWikiServices::getInstance()->getMainConfig();
        $this->collectEmail = (bool)$this->config->get('DiscordCollectEmail');
    }

    /**
     * @inheritDoc
     */
    public function login( ?string &$key, ?string &$secret, ?string &$authUrl ): bool {
        $scopes = ['identify'];

        if ($this->collectEmail) {
            $scopes[] = 'email';
        }

        $authUrl = $this->provider->getAuthorizationUrl(['scope' => $scopes]);

        $secret = $this->provider->getState();

        return true;
    }

    /**
     * @inheritDoc
     */
    public function logout( UserIdentity &$user ): void {
    }

    /**
     * @inheritDoc
     */
    public function getUser( string $key, string $secret, &$errorMessage ) {
        if ( !isset( $_GET['code'] ) ) {
            $errorMessage = 'Discord did not return authorization code';
            return false;
        }

        if (empty( $_GET['state'] ) || ( $_GET['state'] !== $secret) ) {
            $errorMessage = 'Discord did not return authorization state';
            return false;
        }

        try {
            $token = $this->provider->getAccessToken('authorization_code', ['code' => $_GET['code']]);
            $user = $this->provider->getResourceOwner($token);
            $discordUserId = $user->getId();

            // Check if the user already exists
            $existingUser = $this->getExistingUserByDiscordId($discordUserId);
            if ($existingUser) {
                $userInfo = [
                    'name' => $existingUser->getName(),
                    'discord_user_id' => $discordUserId,
                    'realname' => $existingUser->getRealName(),
                    self::SOURCE => self::DISCORD
                ];
            } else {
                $displayName = $this->getUniqueDisplayName($discordUserId);
                $userInfo = [
                    'name' => $displayName,
                    'discord_user_id' => $discordUserId,
                    'realname' => $displayName,
                    self::SOURCE => self::DISCORD
                ];
            }

            if ( $this->collectEmail ) {
                $userInfo['email'] = $user->getEmail();
            }

            // Fetch user roles from Discord
            $userRoles = $this->getDiscordUserRoles($user->getId());
            $userInfo['roles'] = $userRoles;

            return $userInfo;
        } catch ( \Exception $e ) {
            $errorMessage = $e->getMessage();
            return false;
        }
    }

    private function getDiscordUserRoles($discordUserId) {
        // Get the discord client
        $discordClient = $this->getDiscordClient();
        $guildId = $this->config->get('DiscordGuildId');

        $member = $discordClient->guild->getGuildMember(['guild.id' => $guildId, 'user.id' => (int) $discordUserId]);
        return $member->roles;
    }

    private function getDiscordClient() {
        return MediaWikiServices::getInstance()->get('DiscordClient');
    }

    private function getUniqueDisplayName($discordUserId) {
        $discordClient = $this->getDiscordClient();
        $guildId = $this->config->get('DiscordGuildId');
        $member = $discordClient->guild->getGuildMember(['guild.id' => $guildId, 'user.id' => (int) $discordUserId]);
        $displayName = $member->nick ?? $member->user->username;

        $dbProvider = MediaWikiServices::getInstance()->getConnectionProvider();
        $dbr = $dbProvider->getPrimaryDatabase();
        $existingUser = $dbr->selectRow(
            'user',
            ['user_name'],
            ['user_name' => $displayName],
            __METHOD__
        );

        if ($existingUser) {
            // Add suffix if display name exists
            $suffix = 1;
            do {
                $newDisplayName = $displayName . '_' . $suffix;
                $existingUser = $dbr->selectRow(
                    'user',
                    ['user_name'],
                    ['user_name' => $newDisplayName],
                    __METHOD__
                );
                $suffix++;
            } while ($existingUser);
            $displayName = $newDisplayName;
        }

        return $displayName;
    }

    private function getExistingUserByDiscordId($discordUserId) {
        $dbProvider = MediaWikiServices::getInstance()->getConnectionProvider();
        $dbr = $dbProvider->getPrimaryDatabase();
        return $dbr->selectRow(
            'user',
            ['user_id', 'user_name', 'user_real_name'],
            ['user_id' => $discordUserId],
            __METHOD__
        );

    /**
     * @inheritDoc
     */
    public function saveExtraAttributes( int $id ): void {
    }
}
