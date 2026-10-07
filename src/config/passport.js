const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const env = require('./env');
const User = require('../models/User');

const enabled = { google: false, github: false };

// Find or create a local user for a social profile, linking by provider id first, then by email.
async function syncSocialUser({ provider, providerId, email, name, avatar }) {
  const idKey = provider === 'google' ? 'googleId' : 'githubId';

  let user = await User.findByProviderId(provider, providerId);
  if (!user && email) user = await User.findByEmail(email);

  if (!user) {
    return User.create({
      name: (name || email.split('@')[0]).slice(0, 80),
      email,
      avatar,
      role: 'Employee', // social sign-ups never get elevated roles
      isLocal: false,
      [idKey]: providerId,
    });
  }

  // Existing account: link the provider and refresh profile data
  const changes = { [idKey]: providerId };
  if (avatar) changes.avatar = avatar;
  await User.update(user.id, changes);
  return User.findById(user.id);
}

if (env.google.clientId && env.google.clientSecret) {
  enabled.google = true;
  passport.use(
    new GoogleStrategy(
      {
        clientID: env.google.clientId,
        clientSecret: env.google.clientSecret,
        callbackURL: `${env.appUrl}/api/v1/auth/google/callback`,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.find((e) => e.verified)?.value || profile.emails?.[0]?.value;
          if (!email) return done(null, false, { message: 'Google account has no email' });
          const user = await syncSocialUser({
            provider: 'google',
            providerId: profile.id,
            email: email.toLowerCase(),
            name: profile.displayName,
            avatar: profile.photos?.[0]?.value,
          });
          done(null, user);
        } catch (err) {
          done(err);
        }
      }
    )
  );
}

if (env.github.clientId && env.github.clientSecret) {
  enabled.github = true;
  passport.use(
    new GitHubStrategy(
      {
        clientID: env.github.clientId,
        clientSecret: env.github.clientSecret,
        callbackURL: `${env.appUrl}/api/v1/auth/github/callback`,
        scope: ['user:email'],
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value;
          if (!email) return done(null, false, { message: 'GitHub account has no public/verified email' });
          const user = await syncSocialUser({
            provider: 'github',
            providerId: String(profile.id),
            email: email.toLowerCase(),
            name: profile.displayName || profile.username,
            avatar: profile.photos?.[0]?.value,
          });
          done(null, user);
        } catch (err) {
          done(err);
        }
      }
    )
  );
}

module.exports = { passport, enabled };
