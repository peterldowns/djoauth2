# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'Client'
        db.create_table(u'djoauth2_client', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=256)),
            ('description', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('image_url', self.gf('django.db.models.fields.URLField')(max_length=200, null=True, blank=True)),
            ('redirect_uri', self.gf('django.db.models.fields.URLField')(max_length=200)),
            ('key', self.gf('django.db.models.fields.CharField')(default='H2iJZXaT96_~UrfW.xevgd3c4-lwj0', unique=True, max_length=30, db_index=True)),
            ('secret', self.gf('django.db.models.fields.CharField')(default='4npCu9lA2iX~-.yxDVjHN83QfFRG7_', unique=True, max_length=30, db_index=True)),
        ))
        db.send_create_signal(u'djoauth2', ['Client'])

        # Adding model 'Scope'
        db.create_table(u'djoauth2_scope', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=256, db_index=True)),
            ('description', self.gf('django.db.models.fields.TextField')()),
        ))
        db.send_create_signal(u'djoauth2', ['Scope'])

        # Adding model 'AuthorizationCode'
        db.create_table(u'djoauth2_authorizationcode', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('client', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['djoauth2.Client'])),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('date_created', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('lifetime', self.gf('django.db.models.fields.PositiveIntegerField')(default=600)),
            ('invalidated', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('redirect_uri', self.gf('django.db.models.fields.URLField')(max_length=200, null=True, blank=True)),
            ('value', self.gf('django.db.models.fields.CharField')(default='wxJQ6pVqNYKbDiCB_cnTdg.~04tP95', unique=True, max_length=30, db_index=True)),
        ))
        db.send_create_signal(u'djoauth2', ['AuthorizationCode'])

        # Adding M2M table for field scopes on 'AuthorizationCode'
        m2m_table_name = db.shorten_name(u'djoauth2_authorizationcode_scopes')
        db.create_table(m2m_table_name, (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('authorizationcode', models.ForeignKey(orm[u'djoauth2.authorizationcode'], null=False)),
            ('scope', models.ForeignKey(orm[u'djoauth2.scope'], null=False))
        ))
        db.create_unique(m2m_table_name, ['authorizationcode_id', 'scope_id'])

        # Adding model 'AccessToken'
        db.create_table(u'djoauth2_accesstoken', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('client', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['djoauth2.Client'])),
            ('date_created', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('lifetime', self.gf('django.db.models.fields.PositiveIntegerField')(default=3600)),
            ('invalidated', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('authorization_code', self.gf('django.db.models.fields.related.ForeignKey')(blank=True, related_name='access_tokens', null=True, to=orm['djoauth2.AuthorizationCode'])),
            ('refreshable', self.gf('django.db.models.fields.BooleanField')(default=True)),
            ('refresh_token', self.gf('django.db.models.fields.CharField')(null=True, default='Z6atfzj78qlsyX.ouwJ1Kg5BGOIW~2', max_length=30, blank=True, unique=True, db_index=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('value', self.gf('django.db.models.fields.CharField')(default='vXuQgJ0tNszpln.fojDk7cqEY5edh4', unique=True, max_length=30, db_index=True)),
        ))
        db.send_create_signal(u'djoauth2', ['AccessToken'])

        # Adding M2M table for field scopes on 'AccessToken'
        m2m_table_name = db.shorten_name(u'djoauth2_accesstoken_scopes')
        db.create_table(m2m_table_name, (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('accesstoken', models.ForeignKey(orm[u'djoauth2.accesstoken'], null=False)),
            ('scope', models.ForeignKey(orm[u'djoauth2.scope'], null=False))
        ))
        db.create_unique(m2m_table_name, ['accesstoken_id', 'scope_id'])


    def backwards(self, orm):
        # Deleting model 'Client'
        db.delete_table(u'djoauth2_client')

        # Deleting model 'Scope'
        db.delete_table(u'djoauth2_scope')

        # Deleting model 'AuthorizationCode'
        db.delete_table(u'djoauth2_authorizationcode')

        # Removing M2M table for field scopes on 'AuthorizationCode'
        db.delete_table(db.shorten_name(u'djoauth2_authorizationcode_scopes'))

        # Deleting model 'AccessToken'
        db.delete_table(u'djoauth2_accesstoken')

        # Removing M2M table for field scopes on 'AccessToken'
        db.delete_table(db.shorten_name(u'djoauth2_accesstoken_scopes'))


    models = {
        u'auth.group': {
            'Meta': {'object_name': 'Group'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        u'auth.permission': {
            'Meta': {'ordering': "(u'content_type__app_label', u'content_type__model', u'codename')", 'unique_together': "((u'content_type', u'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['contenttypes.ContentType']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        u'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        u'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        u'djoauth2.accesstoken': {
            'Meta': {'object_name': 'AccessToken'},
            'authorization_code': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'access_tokens'", 'null': 'True', 'to': u"orm['djoauth2.AuthorizationCode']"}),
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['djoauth2.Client']"}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'invalidated': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'lifetime': ('django.db.models.fields.PositiveIntegerField', [], {'default': '3600'}),
            'refresh_token': ('django.db.models.fields.CharField', [], {'null': 'True', 'default': "'FM2H.zKZC0GYb~t_PJ7Qfm1pS693XO'", 'max_length': '30', 'blank': 'True', 'unique': 'True', 'db_index': 'True'}),
            'refreshable': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'scopes': ('django.db.models.fields.related.ManyToManyField', [], {'related_name': "'access_tokens'", 'symmetrical': 'False', 'to': u"orm['djoauth2.Scope']"}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['auth.User']"}),
            'value': ('django.db.models.fields.CharField', [], {'default': "'YV79uCqML8Z-NUS~sWmlR_AnOhfKaE'", 'unique': 'True', 'max_length': '30', 'db_index': 'True'})
        },
        u'djoauth2.authorizationcode': {
            'Meta': {'object_name': 'AuthorizationCode'},
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['djoauth2.Client']"}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'invalidated': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'lifetime': ('django.db.models.fields.PositiveIntegerField', [], {'default': '600'}),
            'redirect_uri': ('django.db.models.fields.URLField', [], {'max_length': '200', 'null': 'True', 'blank': 'True'}),
            'scopes': ('django.db.models.fields.related.ManyToManyField', [], {'related_name': "'authorization_codes'", 'symmetrical': 'False', 'to': u"orm['djoauth2.Scope']"}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['auth.User']"}),
            'value': ('django.db.models.fields.CharField', [], {'default': "'niAzbpJoVmavSWe~jZch1DxtME4qBk'", 'unique': 'True', 'max_length': '30', 'db_index': 'True'})
        },
        u'djoauth2.client': {
            'Meta': {'object_name': 'Client'},
            'description': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'image_url': ('django.db.models.fields.URLField', [], {'max_length': '200', 'null': 'True', 'blank': 'True'}),
            'key': ('django.db.models.fields.CharField', [], {'default': "'6i4r1ROgAsYZ.LVax7vX0-zM3Kfhou'", 'unique': 'True', 'max_length': '30', 'db_index': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '256'}),
            'redirect_uri': ('django.db.models.fields.URLField', [], {'max_length': '200'}),
            'secret': ('django.db.models.fields.CharField', [], {'default': "'EjHOeUdAk9BV8Rl6YzxM5oSW4sf7rT'", 'unique': 'True', 'max_length': '30', 'db_index': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['auth.User']"})
        },
        u'djoauth2.scope': {
            'Meta': {'object_name': 'Scope'},
            'description': ('django.db.models.fields.TextField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '256', 'db_index': 'True'})
        }
    }

    complete_apps = ['djoauth2']
