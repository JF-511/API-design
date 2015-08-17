'use strict';

/**
 * @ngdoc overview
 * @name angMaterialApp
 * @description
 * # angMaterialApp
 *
 * Main module of the application.
 */
var app = angular
    .module('angMaterialApp', [
        'ngAnimate',
        'ngAria',
        'ngRoute',
        'ngMaterial',
        'ngMessages'
    ]);

//app.config(function($mdThemingProvider) {
//    $mdThemingProvider.theme('default')
//        .primaryPalette('pink')
//        .accentPalette('orange');
//});

app.config(function ($routeProvider) {
    $routeProvider
        .when('/', {
            templateUrl: 'views/main.html',
            controller: 'MainCtrl'
        })
        .when('/dialog', {
            templateUrl: 'views/dialog.html',
            controller: 'DialogCtrl'
        })
        .otherwise({
            redirectTo: '/'
        });
});

app.directive('menuLink', function() {
    return {
        scope: {
            section: '='
        },
        templateUrl: 'views/partials/menu-link.tmpl.html',
        link: function($scope, $element) {
            var controller = $element.parent().controller();

            $scope.isSelected = function() {
                return controller.isSelected($scope.section);
            };
        }
    };
});

app.directive('menuToggle', function() {
    return {
        scope: {
            section: '='
        },
        templateUrl: 'views/partials/menu-toggle.tmpl.html',
        link: function($scope, $element) {
            var controller = $element.parent().controller();

            $scope.isOpen = function() {
                return controller.isOpen($scope.section);
            };
            $scope.toggle = function() {
                controller.toggleOpen($scope.section);
            };

            var parentNode = $element[0].parentNode.parentNode.parentNode;
            if(parentNode.classList.contains('parent-list-item')) {
                var heading = parentNode.querySelector('h2');
                $element[0].firstChild.setAttribute('aria-describedby', heading.id);
            }
        }
    };
});

app.factory('menu', ['$location', '$rootScope', function($location, $rootScope){

    var sections = [{
        name: 'Home',
        url: '/',
        type: 'link'
    }];

    var demoDocs = [
        {
            name: 'Dialog',
            url: '/dialog'
        }
    ];

    sections.push({
        name: 'Pages',
        pages: demoDocs.sort(sortByName),
        type: 'toggle'
    });

    sections.push();

    function sortByName(a,b) {
        return a.name < b.name ? -1 : 1;
    }

    var self;

    $rootScope.$on('$locationChangeSuccess', onLocationChange);

    return self = {
        sections: sections,

        selectSection: function(section) {
            self.openedSection = section;
        },
        toggleSelectSection: function(section) {
            self.openedSection = (self.openedSection === section ? null : section);
        },
        isSectionSelected: function(section) {
            return self.openedSection === section;
        },

        selectPage: function(section, page) {
            page && page.url && $location.path(page.url);
            self.currentSection = section;
            self.currentPage = page;
        },
        isPageSelected: function(page) {
            return self.currentPage === page;
        }
    };

    function sortByHumanName(a,b) {
        return (a.humanName < b.humanName) ? -1 :
            (a.humanName > b.humanName) ? 1 : 0;
    }

    function onLocationChange() {
        var path = $location.path();

        var matchPage = function(section, page) {
            if (path === page.url) {
                self.selectSection(section);
                self.selectPage(section, page);
            }
        };

        sections.forEach(function(section) {
            if(section.children) {
                // matches nested section toggles, such as API or Customization
                section.children.forEach(function(childSection){
                    if(childSection.pages){
                        childSection.pages.forEach(function(page){
                            matchPage(childSection, page);
                        });
                    }
                });
            }
            else if(section.pages) {
                // matches top-level section toggles, such as Demos
                section.pages.forEach(function(page) {
                    matchPage(section, page);
                });
            }
            else if (section.type === 'link') {
                // matches top-level links, such as "Getting Started"
                matchPage(section, section);
            }
        });
    }
}]);


app.filter('humanizeDoc', function() {
    return function(doc) {
        if (!doc) return;
        if (doc.type === 'directive') {
            return doc.name.replace(/([A-Z])/g, function($1) {
                return '-'+$1.toLowerCase();
            });
        }
        return doc.label || doc.name;
    };
})
