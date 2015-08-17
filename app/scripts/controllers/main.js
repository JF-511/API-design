'use strict';

/**
 * @ngdoc function
 * @name angMaterialApp.controller:MainCtrl
 * @description
 * # MainCtrl
 * Controller of the angMaterialApp
 */
angular.module('angMaterialApp')
    .controller('MainCtrl', ['$scope', '$mdSidenav', '$rootScope', '$timeout', 'menu', function ($scope, $mdSidenav, $rootScope, $timeout, menu) {

      $scope.menu = menu;

      // Methods used by menuLink and menuToggle directives

      $scope.path = path;
      $scope.goHome = goHome;
      $scope.openMenu = openMenu;
      $scope.closeMenu = closeMenu;
      $scope.isSectionSelected = isSectionSelected;

      $rootScope.$on('$locationChangeSuccess', openPage);
      
      $scope.toppings = [
        { name: 'RSASSA-PKCS2-v1_5', number: '2048', type: 'sign, verify', date: '8:55 PM 08/01/15', wanted: false },
        { name: 'ECDSA', number: 'secp256k1', type: 'sign, verify', date: '8:55 PM 08/01/15',  wanted: false },
        { name: 'RSASSA-PKCS2-v1_5', number: '2048', type: 'sign, verify', date: '8:55 PM 08/01/15', wanted: false }
      ];

      // Methods used by menuLink and menuToggle directives
      this.isOpen = isOpen;
      this.isSelected = isSelected;
      this.toggleOpen = toggleOpen;

      var mainContentArea = document.querySelector("[role='main']");

      // *********************
      // Internal methods
      // *********************

      function closeMenu() {
        $timeout(function() { $mdSidenav('left').close(); });
      }

      function openMenu() {
        $timeout(function() { $mdSidenav('left').open(); });
      }

      function path() {
        return $location.path();
      }

      function goHome($event) {
        menu.selectPage(null, null);
        $location.path( '/' );
      }

      function openPage() {
        $scope.closeMenu();
        mainContentArea.focus();
      }

      function isSelected(page) {
        return menu.isPageSelected(page);
      }

      function isSectionSelected(section) {
        var selected = false;
        var openedSection = menu.openedSection;
        if(openedSection === section){
          selected = true;
        }
        else if(section.children) {
          section.children.forEach(function(childSection) {
            if(childSection === openedSection){
              selected = true;
            }
          });
        }
        return selected;
      }

      function isOpen(section) {
        return menu.isSectionSelected(section);
      }

      function toggleOpen(section) {
        menu.toggleSelectSection(section);
      }
    }]);