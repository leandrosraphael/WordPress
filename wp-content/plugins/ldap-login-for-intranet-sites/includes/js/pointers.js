( function($, MAP_LDAP) {

    $(document).on( 'MyAdminPointers.setup_done', function( e, data ) {
        e.stopImmediatePropagation();
        MAP_LDAP.setPlugin( data ); // open first popup
    } );

    $(document).on( 'MyAdminPointers.current_ready', function( e ) {
        e.stopImmediatePropagation();
        MAP_LDAP.openPointer(); // open a popup
    } );

    MAP_LDAP.js_pointers = {};        // contain js-parsed pointer objects
    MAP_LDAP.first_pointer = false;   // contain first pointer anchor jQuery object
    MAP_LDAP.current_pointer = false; // contain current pointer jQuery object
    MAP_LDAP.last_pointer = false;    // contain last pointer jQuery object
    MAP_LDAP.visible_pointers = [];   // contain ids of pointers whose anchors are visible

    MAP_LDAP.hasNext = function( data ) { // check if a given pointer has valid next property
        return typeof data.next === 'string'
            && data.next !== ''
            && typeof MAP_LDAP.js_pointers[data.next].data !== 'undefined'
            && typeof MAP_LDAP.js_pointers[data.next].data.id === 'string';
    };

    MAP_LDAP.isVisible = function( data ) { // check if anchor for given pointer is visible
        return $.inArray( data.id, MAP_LDAP.visible_pointers ) !== -1;
    };

    // given a pointer object, return its the anchor jQuery object if available
    // otherwise return first available, lookin at next property of subsequent pointers
    MAP_LDAP.getPointerData = function( data ) {
        var $target = $( data.anchor_id );
        if ( $.inArray(data.id, MAP_LDAP.visible_pointers) !== -1 ) {
            return { target: $target, data: data };
        }
        $target = false;
        while( MAP_LDAP.hasNext( data ) && ! MAP_LDAP.isVisible( data ) ) {
            data = MAP_LDAP.js_pointers[data.next].data;
            if ( MAP_LDAP.isVisible( data ) ) {
                $target = $(data.anchor_id);
            }
        }
        return MAP_LDAP.isVisible( data )
            ? { target: $target, data: data }
            : { target: false, data: false };
    };

    // take pointer data and setup pointer plugin for anchor element
    MAP_LDAP.setPlugin = function( data ) {
        jQuery('#overlay').show();
        var mo_ldap_support_layout=jQuery('#mo_ldap_support_layout_ldap');
        var select_your_ldap = jQuery('#enable_ldap_login_bckgrnd');
        var set_ldap_filters = jQuery('#ldap_server_url_pointer');
        var test_your_ldap = jQuery('#Test_auth_ldap');
        if ( typeof MAP_LDAP.last_pointer === 'object') {
            MAP_LDAP.last_pointer.pointer('destroy');
            MAP_LDAP.last_pointer = false;
        }
        jQuery(data.anchor_id).css('z-index','2');


        MAP_LDAP.current_pointer = false;
        var pointer_data = MAP_LDAP.getPointerData( data );
        if ( ! pointer_data.target || ! pointer_data.data ) {
            return;
        }
        $target = pointer_data.target;
        data = pointer_data.data;
        $pointer = $target.pointer({
            content: data.title + data.content,
            position: { edge: data.edge, align: data.align },
            close: function() {
                jQuery(data.anchor_id).css('z-index','0');
                jQuery('#overlay').hide();
                $.post( ajaxurl, { pointer: data.id, action: 'dismiss-wp-pointer' } );
            }
        });
        MAP_LDAP.current_pointer = { pointer: $pointer, data: data };
        $(document).trigger( 'MyAdminPointers.current_ready' );
    };

    // scroll the page to current pointer then open it
    MAP_LDAP.openPointer = function() {
        var $pointer = MAP_LDAP.current_pointer.pointer;
        if ( ! typeof $pointer === 'object' ) {
            return;
        }
        $('html, body').animate({ // scroll page to pointer
            scrollTop: $pointer.offset().top-120
        }, 300, function() { // when scroll complete
            MAP_LDAP.last_pointer = $pointer;
            var $widget = $pointer.pointer('widget');
            MAP_LDAP.setNext( $widget, MAP_LDAP.current_pointer.data );
            $pointer.pointer( 'open' ); // open
        });


    };

    // if there is a next pointer set button label to "Next", to "Close" otherwise
    MAP_LDAP.setNext = function( $widget, data ) {
        if ( typeof $widget === 'object' ) {
            var $buttons = $widget.find('.wp-pointer-buttons').eq(0);
            var $close = $buttons.find('a.close').eq(0);
            $button = $close.clone(true, true).removeClass('close');
            $close_button = $close.clone(true, true).removeClass('close');
            $buttons.find('a.close').remove();
            $button.addClass('button').addClass('button-primary');
            $close_button.addClass('button').addClass('button-primary');
            has_next = false;
            if ( MAP_LDAP.hasNext( data ) ) {
                has_next_data = MAP_LDAP.getPointerData(MAP_LDAP.js_pointers[data.next].data);
                has_next = has_next_data.target && has_next_data.data;
                $button.html(MAP_LDAP.next_label).appendTo($buttons);
                $close_button.html(MAP_LDAP.skip_label).appendTo($buttons);
                jQuery($close_button).css('margin-right','10px');
                    jQuery($close_button).click(function (e) {
                        jQuery('#overlay').hide();
                        jQuery('#restart_tour').val('true');
                        jQuery('#show_ldap_pointers').submit();
                    });
            }
            else{
                $close_button.html(MAP_LDAP.close_label).appendTo($buttons);
                    jQuery($close_button).click(function (e) {
                        jQuery('#overlay').hide();
                        jQuery('#restart_tour').val('true');
                        jQuery('#show_ldap_pointers').submit();
                    });
            }
           
            jQuery($button).click(function () {
                switch (data.anchor_id) {
                    case '#ldap_default_tab_pointer' :
                        document.getElementById('ldap_default_tab_pointer').className = 'nav-tab';
                        document.getElementById('ldap_signin_settings_tab_pointer').className = 'nav-tab nav-tab active';
                        document.getElementById('ldap_configuration_tab').style.display = 'none';
                        document.getElementById('signin_settings_tab').style.display = 'block';
                        break;
                    case '#ldap_signin_settings_tab_pointer':
                        document.getElementById('ldap_signin_settings_tab_pointer').className = 'nav-tab';
                        document.getElementById('ldap_multiple_directories_tab_pointer').className = 'nav-tab nav-tab active';
                        document.getElementById('signin_settings_tab').style.display = 'none';
                        document.getElementById('ldap_multiple_directories_tab').style.display = 'block';
                        break;
                    case '#ldap_multiple_directories_tab_pointer':
                        document.getElementById('ldap_multiple_directories_tab_pointer').className = 'nav-tab';
                        document.getElementById('ldap_role_mapping_tab_pointer').className = 'nav-tab nav-tab active';
                        document.getElementById('ldap_multiple_directories_tab').style.display = 'none';
                        document.getElementById('role_mapping_tab').style.display = 'block';
                        break;
                    case '#ldap_role_mapping_tab_pointer':
                        document.getElementById('ldap_role_mapping_tab_pointer').className = 'nav-tab';
                        document.getElementById('ldap_attribute_mapping_tab_pointer').className = 'nav-tab nav-tab active';
                        document.getElementById('role_mapping_tab').style.display = 'none';
                        document.getElementById('attribute_mapping_tab').style.display = 'block';
                        break;
                    case '#ldap_attribute_mapping_tab_pointer' :
                        document.getElementById('ldap_attribute_mapping_tab_pointer').className = 'nav-tab';
                        document.getElementById('attribute_mapping_tab').style.display = 'block';
                        break;
                    case '#mo_ldap_add_on_layout' :
                        document.getElementById('ldap_feature_request_tab_pointer').className = 'nav-tab nav-tab active';
                        document.getElementById('attribute_mapping_tab').style.display = 'none';
                        document.getElementById('feature_request_tab').style.display = 'block';
                        break;
                    case '#ldap_feature_request_tab_pointer':
                        document.getElementById('ldap_feature_request_tab_pointer').className = 'nav-tab';
                        document.getElementById('ldap_config_settings_tab_pointer').className =  'nav-tab nav-tab active';
                        document.getElementById('feature_request_tab').style.display = 'none';
                        document.getElementById('export_tab').style.display = 'block';
                        break;
                    case '#ldap_config_settings_tab_pointer':
                        document.getElementById('ldap_config_settings_tab_pointer').className = 'nav-tab';
                        document.getElementById('ldap_User_Report_tab_pointer').className = 'nav-tab nav-tab active';
                        document.getElementById('export_tab').style.display = 'none';
                        document.getElementById('Users_Report').style.display = 'block';
                        break;
                    case '#ldap_User_Report_tab_pointer':
                        document.getElementById('ldap_User_Report_tab_pointer').className = 'nav-tab';
                        document.getElementById('Users_Report').style.display = 'none';
                        document.getElementById('ldap_configuration_tab').style.display = 'block';
                        break;
                    case '#configure-restart-plugin-tour' :
                        jQuery('#restart_tour').val('true');
                        jQuery('#show_ldap_pointers').submit();
                        break;
                }
                if ( MAP_LDAP.hasNext( data ) ) {
                    MAP_LDAP.setPlugin( MAP_LDAP.js_pointers[data.next].data );
                }
            });
        }
    };

    $(MAP_LDAP.pointers).each(function(index, pointer) { // loop pointers data
        if( ! $().pointer ) return;      // do nothing if pointer plugin isn't available
        MAP_LDAP.js_pointers[pointer.id] = { data: pointer };
        var $target = $(pointer.anchor_id);
        if ( $target.length && $target.is(':visible') ) { // anchor exists and is visible?
            MAP_LDAP.visible_pointers.push(pointer.id);
            if ( ! MAP_LDAP.first_pointer ) {
                MAP_LDAP.first_pointer = pointer;
            }
        }
        if ( index === ( MAP_LDAP.pointers.length - 1 ) && MAP_LDAP.first_pointer ) {
            $(document).trigger( 'MyAdminPointers.setup_done', MAP_LDAP.first_pointer );
        }
    });

} )(jQuery, MyAdminPointers); // MyAdminPointers is passed by `wp_localize_script`