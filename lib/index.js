'use strict';

var path = require('path');

var loopback = require('loopback');
var DataModel = loopback.PersistedModel || loopback.DataModel;

function loadModel(jsonFile) {
  var modelDefinition = require(jsonFile);
  return DataModel.extend(modelDefinition.name,
    modelDefinition.properties,
    {
      relations: modelDefinition.relations,
    });
}

var CasUserModel = loadModel('./models/cas-user.json');

exports.CasUser = require('./models/cas-user')(CasUserModel);

exports.CasUser.autoAttach = 'db';

exports.CasConfigurator = require('./cas-configurator');
