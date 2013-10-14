# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'Client'
        db.create_table('djoauth2_client', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=256)),
            ('description', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('image_url', self.gf('django.db.models.fields.URLField')(max_length=200, null=True, blank=True)),
            ('redirect_uri', self.gf('django.db.models.fields.URLField')(max_length=200)),
            ('key', self.gf('django.db.models.fields.CharField')(default='fZhQXI_GsinrAl7x~.duMTvkm5SbCV', unique=True, max_length=30, db_index=True)),
            ('secret', self.gf('django.db.models.fields.CharField')(default='CYQIBm6dEKA-G_5F0R9Ho~ZMqp1jvO', unique=True, max_length=30, db_index=True)),
        ))
        db.send_create_signal('djoauth2', ['Client'])

        # Adding model 'Scope'
        db.create_table('djoauth2_scope', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=256, db_index=True)),
            ('description', self.gf('django.db.models.fields.TextField')()),
        ))
        db.send_create_signal('djoauth2', ['Scope'])

        # Adding model 'AuthorizationCode'
        db.create_table('djoauth2_authorizationcode', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('client', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['djoauth2.Client'])),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('date_created', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('lifetime', self.gf('django.db.models.fields.PositiveIntegerField')(default=600)),
            ('invalidated', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('redirect_uri', self.gf('django.db.models.fields.URLField')(max_length=200, null=True, blank=True)),
            ('value', self.gf('django.db.models.fields.CharField')(default='VaQofWvI7HRUNF4x1Ls8TMpu9bh2~j', unique=True, max_length=30, db_index=True)),
        ))
        db.send_create_signal('djoauth2', ['AuthorizationCode'])

        # Adding M2M table for field scopes on 'AuthorizationCode'
        db.create_table('djoauth2_authorizationcode_scopes', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('authorizationcode', models.ForeignKey(orm['djoauth2.authorizationcode'], null=False)),
            ('scope', models.ForeignKey(orm['djoauth2.scope'], null=False))
        ))
        db.create_unique('djoauth2_authorizationcode_scopes', ['authorizationcode_id', 'scope_id'])

        # Adding model 'AccessToken'
        db.create_table('djoauth2_accesstoken', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('client', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['djoauth2.Client'])),
            ('date_created', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('lifetime', self.gf('django.db.models.fields.PositiveIntegerField')(default=3600)),
            ('invalidated', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('authorization_code', self.gf('django.db.models.fields.related.ForeignKey')(blank=True, related_name='access_tokens', null=True, to=orm['djoauth2.AuthorizationCode'])),
            ('refreshable', self.gf('django.db.models.fields.BooleanField')(default=True)),
            ('refresh_token', self.gf('django.db.models.fields.CharField')(null=True, default='EsmhYxg1bfXI20zJ93FvBSriu5UH4j', max_length=30, blank=True, unique=True, db_index=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('value', self.gf('django.db.models.fields.CharField')(default='CnK9NrzHYOV5_E0Xe8WmGjSkv3q4Mi', unique=True, max_length=30, db_index=True)),
        ))
        db.send_create_signal('djoauth2', ['AccessToken'])

        # Adding M2M table for field scopes on 'AccessToken'
        db.create_table('djoauth2_accesstoken_scopes', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('accesstoken', models.ForeignKey(orm['djoauth2.accesstoken'], null=False)),
            ('scope', models.ForeignKey(orm['djoauth2.scope'], null=False))
        ))
        db.create_unique('djoauth2_accesstoken_scopes', ['accesstoken_id', 'scope_id'])


    def backwards(self, orm):
        # Deleting model 'Client'
        db.delete_table('djoauth2_client')

        # Deleting model 'Scope'
        db.delete_table('djoauth2_scope')

        # Deleting model 'AuthorizationCode'
        db.delete_table('djoauth2_authorizationcode')

        # Removing M2M table for field scopes on 'AuthorizationCode'
        db.delete_table('djoauth2_authorizationcode_scopes')

        # Deleting model 'AccessToken'
        db.delete_table('djoauth2_accesstoken')

        # Removing M2M table for field scopes on 'AccessToken'
        db.delete_table('djoauth2_accesstoken_scopes')


    models = {
        'auth.group': {
            'Meta': {'object_name': 'Group'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        'auth.permission': {
            'Meta': {'ordering': "('content_type__app_label', 'content_type__model', 'codename')", 'unique_together': "(('content_type', 'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['contenttypes.ContentType']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        'djoauth2.accesstoken': {
            'Meta': {'object_name': 'AccessToken'},
            'authorization_code': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'access_tokens'", 'null': 'True', 'to': "orm['djoauth2.AuthorizationCode']"}),
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['djoauth2.Client']"}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'invalidated': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'lifetime': ('django.db.models.fields.PositiveIntegerField', [], {'default': '3600'}),
            'refresh_token': ('django.db.models.fields.CharField', [], {'null': 'True', 'default': "'dypx1aPg9hQtv7b8R43kn6cqV~EFHN'", 'max_length': '30', 'blank': 'True', 'unique': 'True', 'db_index': 'True'}),
            'refreshable': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'scopes': ('django.db.models.fields.related.ManyToManyField', [], {'related_name': "'access_tokens'", 'symmetrical': 'False', 'to': "orm['djoauth2.Scope']"}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"}),
            'value': ('django.db.models.fields.CharField', [], {'default': "'mB9DAWsItGpFOC~T6af1o4geiR7lHK'", 'unique': 'True', 'max_length': '30', 'db_index': 'True'})
        },
        'djoauth2.authorizationcode': {
            'Meta': {'object_name': 'AuthorizationCode'},
            'client': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['djoauth2.Client']"}),
            'date_created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'invalidated': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'lifetime': ('django.db.models.fields.PositiveIntegerField', [], {'default': '600'}),
            'redirect_uri': ('django.db.models.fields.URLField', [], {'max_length': '200', 'null': 'True', 'blank': 'True'}),
            'scopes': ('django.db.models.fields.related.ManyToManyField', [], {'related_name': "'authorization_codes'", 'symmetrical': 'False', 'to': "orm['djoauth2.Scope']"}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"}),
            'value': ('django.db.models.fields.CharField', [], {'default': "'TfOsDkoZr.ley9NzYPuX~IEAQc4aK1'", 'unique': 'True', 'max_length': '30', 'db_index': 'True'})
        },
        'djoauth2.client': {
            'Meta': {'object_name': 'Client'},
            'description': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'image_url': ('django.db.models.fields.URLField', [], {'max_length': '200', 'null': 'True', 'blank': 'True'}),
            'key': ('django.db.models.fields.CharField', [], {'default': "'~ozx3OEg4qHt_-jXi.ubarMdB6RfV1'", 'unique': 'True', 'max_length': '30', 'db_index': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '256'}),
            'redirect_uri': ('django.db.models.fields.URLField', [], {'max_length': '200'}),
            'secret': ('django.db.models.fields.CharField', [], {'default': "'SARM5tag_qQunmovi-VJHs2Nz3GdbO'", 'unique': 'True', 'max_length': '30', 'db_index': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"})
        },
        'djoauth2.scope': {
            'Meta': {'object_name': 'Scope'},
            'description': ('django.db.models.fields.TextField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '256', 'db_index': 'True'})
        }
    }

    complete_apps = ['djoauth2']