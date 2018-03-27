

function init_select_target() {
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", "/show_targets", true);
    xmlhttp.onload = function(e) {
        if(this.status == 200||this.status == 304){
            $(".dropdown-menu:first").empty();
            var targets;
            targets = JSON.parse(xmlhttp.responseText);
            for (i in targets){
            //targets[i]
               $(".dropdown-menu:first").prepend("<li><a onclick=\"clickselect(this)\">" + targets[i] + "</a></li>");
            };
        }
     };
     xmlhttp.send();
}

function init_added_domains() {
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", "/show_domains", true);
    xmlhttp.onload = function(e) {
        if(this.status == 200||this.status == 304){
            $("#added_domains").empty();
            var domains;
            domains = JSON.parse(xmlhttp.responseText);
            for (i in domains){
            //targets[i]
               $("#added_domains").prepend("<li><a>" + domains[i] + "</a></li>");
            };
        }
     };
     xmlhttp.send();
}


function inittable() {
    $("[type='inittable']").empty();
    $("[type='inittable']").prepend("<table id=\"table\"\n           data-toolbar=\"#toolbar\"\n           data-search=\"true\"\n           data-show-refresh=\"true\"\n           data-show-toggle=\"true\"\n           data-show-columns=\"true\"\n           data-show-export=\"true\"\n           data-detail-view=\"true\"\n           data-show-pagination-switch=\"true\"\n           data-pagination=\"true\"\n           data-id-field=\"id\"\n           data-page-list=\"[10, 25, 50, 100, ALL]\">\n    </table>");
}

function init_ipdomin_Table() {
    inittable();
    var $table = $('#table');
    $table.bootstrapTable({
        url: '/get_iplist',
        sidePagination: "server",
        columns: [{
            field: 'id',
            title: 'id',
        },
        {
            field: 'domain',
            title: 'domain',
            sortable: true,
            align: 'center',
            editable: {
                type: 'text',
                title: 'domain',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        },
        {
            field: 'ip',
            title: 'ip',
            sortable: true,
            align: 'center',
            editable: {
                type: 'text',
                title: 'ip',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        }]
    });
}

function init_ipport_Table() {
    inittable();
    var $table = $('#table');
    $table.bootstrapTable({
        url: '/get_ip_port',
        sidePagination: "server",
        columns: [{
            field: '_id',
            title: 'id',
        },
        {
            field: 'domain',
            title: 'domain',
            sortable: true,
            align: 'center',
            editable: {
                type: 'text',
                title: 'domain',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        },
        {
            field: 'ip',
            title: 'ip',
            sortable: true,
            align: 'center',
            editable: {
                type: 'text',
                title: 'ip',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        },
        {
            field: 'ports',
            title: 'ports',
            align: 'center',
        }]
    });
}

function init_service_Table() {
    inittable();
    var $table = $('#table');
    $table.bootstrapTable({
        url: '/get_service',
        sidePagination: "server",
        columns: [{
            field: 'id',
            title: 'id',
        },
        {
            field: 'ip_domain',
            title: 'ip_domain',
            sortable: true,
            align: 'center',
        },
        {
            field: 'port',
            title: 'port',
            align: 'center',
        },
        {
            field: 'type',
            title: 'type',
            sortable: true,
            align: 'center',
            editable: {
                type: 'text',
                title: 'type',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        },
        {
            field: 'version',
            title: 'version',
            sortable: true,
            align: 'center',
            editable: {
                type: 'text',
                title: 'version',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        }]
    });
}

function init_httpservice_Table() {
    inittable();
    var $table = $('#table');
    $table.bootstrapTable({
        url: '/get_http_vul',
        sidePagination: "server",
        columns: [{
            field: 'id',
            title: 'id',
        },
        {
            field: 'domain_url',
            title: 'domain_url',
            sortable: true,
            align: 'center',
            editable: {
                type: 'text',
                title: 'domain/url',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        },
        {
            field: 'title',
            title: 'title',
            sortable: true,
            align: 'center',
            editable: {
                type: 'text',
                title: 'title',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        },
        {
            field: 'tiny_scan',
            title: 'tiny_scan',
            editable: {
                type: 'text',
                title: 'tiny_scan',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        }]
    });
}

function init_tinyscan_Table() {
    inittable();
    var $table = $('#table');
    $table.bootstrapTable({
        url: '/get_tiny_scan',
        sidePagination: "server",
        columns: [
        {
            field: 'url',
            title: 'url',
            sortable: true,
            align: 'center',
            editable: {
                type: 'text',
                title: 'url',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        },
        {
            field: 'domain',
            title: 'domain',
            sortable: true,
            align: 'center',
        },
        {
            field: 'title',
            title: 'title',
            editable: {
                type: 'text',
                title: 'vulinfo',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        }]
    });
}

function init_portvul_Table() {
    inittable();
    var $table = $('#table');
    $table.bootstrapTable({
        url: '/get_port_vul',
        sidePagination: "server",
        columns: [{
            field: 'id',
            title: 'id',
        },
        {
            field: 'ip_domain',
            title: 'ip_domain',
            sortable: true,
            align: 'center',
            editable: {
                type: 'text',
                title: 'ip/domain',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        },
        {
            field: 'port',
            title: 'port',
            sortable: true,
            align: 'center',
            editable: {
                type: 'text',
                title: 'port',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        },
        {
            field: 'vulinfo',
            title: 'vulinfo',
            editable: {
                type: 'text',
                title: 'vulinfo',
                validate: function(value) {
                    value = $.trim(value);
                    if (!value) {
                        return 'This field is required';
                    }
                    var data = $table.bootstrapTable('getData'),
                    index = $(this).parents('tr').data('index');
                    update_domain_ip(data[index]);
                    return '';
                }
            },
        }]
    });
}

function update_domain_ip(data) {
    console.log(JSON.stringify(data));
    var xmlhttp = new XMLHttpRequest();
	xmlhttp.open("POST", "/update_domain_ip", true);
    xmlhttp.send(JSON.stringify(data));
}
function clicknav(obj) {
    old = $("li.active");
    old.removeAttr("class");
    obj.setAttribute("class", "active");
    console.log(obj.type);
    switch (Number(obj.type)) {
    case 0:
        init_ipdomin_Table();
        break;
    case 1:
        init_ipport_Table();
        break;
    case 2:
        init_service_Table();
        break;
    case 3:
        init_httpservice_Table();
        break;
    case 4:
        init_tinyscan_Table();
        break;
    case 5:
        init_portvul_Table();
        break;
    }
}
function clickselect(obj) {
    $("a.dropdown-toggle:first").text(obj.innerHTML);
    document.cookie="target="+obj.innerHTML;
    init_added_domains();
    show_progress();
}

function click_action(obj){
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", obj.type,true);
    xmlhttp.onload = function(e) {
        console.log(xmlhttp.responseText)
        if(this.status == 200||this.status == 304){
            if (xmlhttp.responseText[0] == '1'){
                alert('success')
            }else{
                alert('defeated')
            }
        }
    }
    xmlhttp.send();
}


function operateFormatter(value, row, index) {
    return ['<a class="like" href="javascript:void(0)" title="Like">', '<i class="glyphicon glyphicon-heart"></i>', '</a>  '].join('');
}

window.operateEvents = {
    'click .like': function(e, value, row, index) {
        console.log('send scan, row: ' + JSON.stringify(row));
    }
};

function portinfoFormatter(value, row, index) {
    return ['<a class="like" href="javascript:void(0)" title="Like">', '<i class="glyphicon glyphicon-heart"></i>', '</a>  '].join('');
}

function show_progress(){
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", "/show_progress", true);
    xmlhttp.onload = function(e) {
        if(this.status == 200||this.status == 304){
            var info;
            info = JSON.parse(xmlhttp.responseText);
            $("#progress-bar").attr({
              "aria-valuenow" :  info[0],
              "style" : info[1]
            });
            $("#progress-bar").text(info[2]);
        }
     };
     xmlhttp.send();
}

window.portinfoEvents = {
    'click .like': function(e, value, row, index) {
        console.log('send scan, row: ' + JSON.stringify(row));
    }
};