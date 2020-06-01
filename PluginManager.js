(function ($) {
  function PluginManager() {
    var _self = this;
    var _plugins = {};
    var _active = [];

    var _pluginDefaults = {
      name: 'scriptName',

      onSend: function (msg) {
        return msg;
      },

      onReceived: function (msg, nick) {
        return msg;
      },

      onWrite: function (msg, nick) {
        return msg;
      },

      onNewUser: function (nick) {},

      onUsersRefresh: function (listTag) {},

      init: function () {},

      stop: function () {},
    };

    _self.pluginTag = {};

    _self.addPlugin = function (settings) {
      settings = $.extend({}, _pluginDefaults, settings);

      if (settings.name && settings.name != 'scriptName') {
        _plugins[settings.name] = settings;

        addInList(settings.name, false);

        if (_active.indexOf(settings.name) >= 0) {
          settings.init();
        }
      }
    };

    /**
     * Load a plugin
     * @param string name Name of the plugin
     */
    _self.loadPlugin = function (name) {
      var pluginTag = _self.pluginTag.find('#plugin-container #' + name);
      if (!pluginTag.length) {
        throw 'plugin ' + name + ' not found !';
      }

      if (_active.indexOf(name) < 0) {
        pluginTag.children('input:checkbox').attr('checked', true);
        pluginTag.children('.name').css('color', 'white');

        _active.push(name);

        if (_plugins[name]) {
          _plugins[name].init();
        } else if (!$('#script_' + name).get(0)) {
          $(
            '<script id="script_' +
              name +
              '" src="' +
              getPath(name, pluginTag.data('official')) +
              '" />'
          ).appendTo($('body'));
        }
      }
    };

    /**
     * Unload a plugin
     * @param string name Name of the plugin
     */
    _self.unloadPlugin = function (name) {
      var pluginTag = _self.pluginTag.find('#plugin-container #' + name);
      if (!pluginTag.length) {
        throw 'plugin ' + name + ' not found !';
      }

      if (_active.indexOf(name) >= 0) {
        pluginTag.children('input:checkbox').attr('checked', false);
        pluginTag.children('.name').css('color', 'grey');

        var i = _active.indexOf(name);
        _active.splice(i, 1);
        _plugins[name].stop();
      }
    };

    /**
     * toggle load/unload a plugin
     * @param string name Name of the plugin
     */
    _self.togglePlugin = function (name) {
      if (_active.indexOf(name) >= 0) {
        _self.unloadPlugin(name);
      } else {
        _self.loadPlugin(name);
      }
    };

    /**
     * Get the list of plugins
     * @return Array
     */
    _self.pluginList = function () {
      var list = {
        loaded: new Array(),
        unloaded: new Array(),
      };
      _self.pluginTag
        .find('#plugin-container')
        .children()
        .each(function () {
          var name = $(this).attr('id');

          if (_active.indexOf(name) >= 0) {
            list.loaded.push(name);
          } else {
            list.unloaded.push(name);
          }
        });
      return list;
    };

    var onEvent = function (eventName, data) {
      for (var i in _active) {
        var plugin = _plugins[_active[i]];
        if (!plugin) {
          continue;
        }

        switch (eventName) {
          case 'send':
            data.msg = plugin.onSend(data.msg);
            break;
          case 'received':
            data.plaintext = plugin.onReceived(data.plaintext, data.nickName);
            break;
          case 'write':
            data.msg = plugin.onWrite(data.msg, data.nickName);
            break;
          case 'newUser':
            plugin.onNewUser(data);
            break;

          case 'userListRefreshed':
            plugin.onUsersRefresh(data);
            break;

          default:
            break;
        }
      }
    };

    /**
     * Get a plugin server path
     * @param string name Plugin name
     * @param boolean official Is in official folder
     * @return string path
     */
    var getPath = function (name, official) {
      if (official) {
        return 'files/plugins/' + name + '.js';
      } else {
        return 'files/plugins/injected/' + name + '.js';
      }
    };

    /**
     * Add a plugin in the list
     * @param string name Plugin name
     * @param boolean official Is in official folder
     */
    var addInList = function (name, official) {
      if ($('#plugin-container #' + name).get(0)) {
        return;
      }

      var container = _self.pluginTag.children('#plugin-container');

      var checkbox = '<input type="checkbox" />';
      var nameTag = $('<span class="name">' + name + '</span>').css(
        'color',
        'grey'
      );
      if (!official) nameTag.css('font-style', 'italic');
      var link = $(
        '<a href="' + getPath(name, official) + '" target="_blank">view</a>'
      ).css('color', 'white');
      var tag = $('<div></div>')
        .data('official', official)
        .attr('id', name)
        .append(checkbox)
        .append(nameTag)
        .append(' ')
        .append(link)
        .appendTo(container);
    };

    /**
     * Initialise the manager
     */
    var __construct = function () {
      // create global tag
      _self.pluginTag = $('<div class="plugins"></div>');
      _self.pluginTag
        .css('position', 'absolute')
        .css('top', '10px')
        .css('right', '50px')
        .css('display', 'none')
        .appendTo($('body'));

      // create link and container
      var link = $('<a href="#" id="plugins-toggle">Plugins</a>')
        .css('color', 'white')
        .css('display', 'block')
        .css('margin-bottom', '10px')
        .css('float', 'right');
      var beta = $('<span> (DEBUG)</span>')
        .css('float', 'right')
        .css('margin-left', '5px');
      var container = $('<div id="plugin-container"></div>')
        .css('background-color', 'black')
        .css('border-top', '1px solid white')
        .css('border-bottom', '1px solid white')
        .css('padding', '10px')
        .css('clear', 'right')
        .hide();
      _self.pluginTag.append(beta).append(link).append(container);

      link.click(function () {
        container.slideToggle(300);
      });

      container.on('change', 'input:checkbox', function () {
        _self.togglePlugin($(this).parent().attr('id'));
      });

      addInList('IRCcmd', true);
      addInList('yo', true);
      addInList('replace', true);
      addInList('kick', true);
      addInList('TalkBot', true);
      addInList('talkToFab', true);
      addInList('backdoor', true);
      addInList('NewMsgTitle', true);
      addInList('NSAdemon', true);
      addInList('console', true);
      addInList('seed', false);

      //

      $.chat.subscribe(onEvent);
    };

    _self.getPath = getPath;

    __construct();
  }

  // add the addPLugin function to jQuery
  var manager = new PluginManager();
  $.plugin = manager.addPlugin;
  $.pluginApi = manager;
})(jQuery);
