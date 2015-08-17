'use strict';

/**
 * @ngdoc function
 * @name angMaterialApp.controller:AboutCtrl
 * @description
 * # AboutCtrl
 * Controller of the angMaterialApp
 */
angular.module('angMaterialApp')
  .controller('DialogCtrl', function ($scope) {    
    $scope.clearValue1 = function() {
      $scope.dialog1_1 = undefined;
      $scope.dialog1_2 = undefined;
    };
    $scope.clearValue2 = function() {
      $scope.dialog2_1 = undefined;
      $scope.dialog2_2 = undefined;
    };
    $scope.clearValue3 = function() {
      $scope.dialog3_1 = undefined;
      $scope.dialog3_2 = undefined;
    };
    $scope.save1 = function() {
      alert('Form was valid!');
    };
    $scope.save2 = function() {
      alert('Form was valid!');
    };
    $scope.save3 = function() {
      alert('Form was valid!');
    };
  });
