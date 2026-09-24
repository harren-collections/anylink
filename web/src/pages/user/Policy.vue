<template>
  <div>
    <el-card>
      <el-form :inline="true">
        <el-form-item>
          <el-button size="small" type="primary" icon="el-icon-plus" @click="handleEdit('')">添加
          </el-button>
        </el-form-item>
      </el-form>

      <el-table ref="multipleTable" :data="tableData" border>

        <el-table-column sortable="true" prop="id" label="ID" width="60">
        </el-table-column>

        <el-table-column prop="username" label="用户名">
        </el-table-column>
        <el-table-column prop="allow_lan" label="本地网络">
          <template slot-scope="scope">
            <el-switch v-model="scope.row.allow_lan" disabled>
            </el-switch>
          </template>
        </el-table-column>
        <el-table-column prop="bandwidth" label="带宽限制" width="90">
          <template slot-scope="scope">
            <el-row v-if="scope.row.bandwidth > 0">{{ convertBandwidth(scope.row.bandwidth, 'BYTE', 'Mbps') }} Mbps
            </el-row>
            <el-row v-else-if="scope.row.bandwidth === 0">不限速</el-row>
            <el-row v-else></el-row>
          </template>
        </el-table-column>

        <el-table-column prop="client_dns" label="客户端DNS" width="160">
          <template slot-scope="scope">
            <el-row v-for="(item, inx) in scope.row.client_dns" :key="inx">{{ item.val }}</el-row>
          </template>
        </el-table-column>

        <el-table-column prop="route_include" label="路由包含" width="200">
          <template slot-scope="scope">
            <el-row v-for="(item, inx) in scope.row.route_include.slice(0, readMinRows)" :key="inx">{{ item.val
              }}</el-row>
            <div v-if="scope.row.route_include.length > readMinRows">
              <div v-if="readMore[`ri_${scope.row.id}`]">
                <el-row v-for="(item, inx) in scope.row.route_include.slice(readMinRows)" :key="inx">{{ item.val
                  }}</el-row>
              </div>
              <el-button size="mini" type="text" @click="toggleMore(`ri_${scope.row.id}`)">{{
                readMore[`ri_${scope.row.id}`] ? "▲ 收起" : "▼ 更多" }}</el-button>
            </div>
          </template>
        </el-table-column>

        <el-table-column prop="route_exclude" label="路由排除" width="200">
          <template slot-scope="scope">
            <el-row v-for="(item, inx) in scope.row.route_exclude.slice(0, readMinRows)" :key="inx">{{ item.val
              }}</el-row>
            <div v-if="scope.row.route_exclude.length > readMinRows">
              <div v-if="readMore[`re_${scope.row.id}`]">
                <el-row v-for="(item, inx) in scope.row.route_exclude.slice(readMinRows)" :key="inx">{{ item.val
                  }}</el-row>
              </div>
              <el-button size="mini" type="text" @click="toggleMore(`re_${scope.row.id}`)">{{
                readMore[`re_${scope.row.id}`] ? "▲ 收起" : "▼ 更多" }}</el-button>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="link_acl" label="权限控制" width="200">
          <template slot-scope="scope">
            <el-row v-for="(item, inx) in scope.row.link_acl" :key="inx">
              {{ item.action }} {{ item.protocol }} {{ item.val }} {{ item.port ? ':' + item.port : '' }}
            </el-row>
            <div v-if="!scope.row.link_acl || scope.row.link_acl.length === 0">
              <span style="color: #909399;"></span>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="70">
          <template slot-scope="scope">
            <el-tag v-if="scope.row.status === 1" type="success">可用</el-tag>
            <el-tag v-else type="danger">停用</el-tag>
          </template>

        </el-table-column>

        <el-table-column prop="updated_at" label="更新时间" :formatter="tableDateFormat">
        </el-table-column>

        <el-table-column label="操作" width="150">
          <template slot-scope="scope">
            <el-button size="mini" type="primary" @click="handleEdit(scope.row)">编辑
            </el-button>

            <el-popconfirm style="margin-left: 10px" @confirm="handleDel(scope.row)" title="确定要删除用户策略项吗？">
              <el-button slot="reference" size="mini" type="danger">删除
              </el-button>
            </el-popconfirm>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination background layout="prev, pager, next" :pager-count="11" @current-change="pageChange"
        :current-page="page" :total="count">
      </el-pagination>

    </el-card>

    <!--新增、修改弹出框-->
    <el-dialog :close-on-click-modal="false" title="用户策略" :visible.sync="user_edit_dialog" width="850px" top="50px"
      @close='closeDialog' center>

      <el-form :model="ruleForm" :rules="rules" ref="ruleForm" label-width="100px" class="ruleForm">
        <el-tabs v-model="activeTab" :before-leave="beforeTabLeave">
          <el-tab-pane label="通用" name="general">
            <el-form-item label="ID" prop="id">
              <el-input v-model="ruleForm.id" disabled></el-input>
            </el-form-item>

            <el-form-item label="用户名" prop="username">
              <el-input v-model="ruleForm.username" :disabled="ruleForm.id > 0"></el-input>
            </el-form-item>

            <el-form-item label="带宽限制" prop="bandwidth_format" style="width:260px;">
              <div style="display: flex; align-items: center;">
                <el-input v-model="ruleForm.bandwidth_format"
                  oninput="value= value.match(/\d+(\.\d{0,2})?/) ? value.match(/\d+(\.\d{0,2})?/)[0] : ''">
                  <template slot="append">Mbps</template>
                </el-input>
                <el-tooltip effect="dark" placement="top">
                  <div slot="content">
                    0：不限速<br>
                    留空：使用组策略<br>
                  </div>
                  <i class="el-icon-question" style="margin-left: 10px; cursor: pointer;"></i>
                </el-tooltip>
              </div>
            </el-form-item>

            <el-form-item label="本地网络" prop="allow_lan">
              <el-switch v-model="ruleForm.allow_lan">
              </el-switch>
            </el-form-item>
            <el-form-item label="客户端DNS" prop="client_dns">
              <el-row class="msg-info">
                <el-col :span="20">输入IP格式如: 192.168.0.10</el-col>
                <el-col :span="4">
                  <el-button size="mini" type="success" icon="el-icon-plus" circle
                    @click.prevent="addDomain(ruleForm.client_dns)"></el-button>
                </el-col>
              </el-row>
              <el-row v-for="(item, index) in ruleForm.client_dns" :key="index" style="margin-bottom: 5px" :gutter="10">
                <el-col :span="10">
                  <el-input v-model="item.val"></el-input>
                </el-col>
                <el-col :span="12">
                  <el-input v-model="item.note" placeholder="备注"></el-input>
                </el-col>
                <el-col :span="2">
                  <el-button size="mini" type="danger" icon="el-icon-minus" circle
                    @click.prevent="removeDomain(ruleForm.client_dns, index)"></el-button>
                </el-col>
              </el-row>
            </el-form-item>
            <el-form-item label="状态" prop="status">
              <el-radio-group v-model="ruleForm.status">
                <el-radio :label="1" border>启用</el-radio>
                <el-radio :label="0" border>停用</el-radio>
              </el-radio-group>
            </el-form-item>
          </el-tab-pane>

          <el-tab-pane label="路由设置" name="route">
            <el-form-item label="包含路由" prop="route_include">
              <el-row class="msg-info">
                <el-col :span="20">输入CIDR格式如: 192.168.1.0/24</el-col>
                <el-col :span="4">
                  <el-button size="mini" type="success" icon="el-icon-plus" circle
                    @click.prevent="addDomain(ruleForm.route_include)"></el-button>
                </el-col>
              </el-row>
              <el-row v-for="(item, index) in ruleForm.route_include" :key="index" style="margin-bottom: 5px"
                :gutter="10">
                <el-col :span="10">
                  <el-input v-model="item.val"></el-input>
                </el-col>
                <el-col :span="12">
                  <el-input v-model="item.note" placeholder="备注"></el-input>
                </el-col>
                <el-col :span="2">
                  <el-button size="mini" type="danger" icon="el-icon-minus" circle
                    @click.prevent="removeDomain(ruleForm.route_include, index)"></el-button>
                </el-col>
              </el-row>
            </el-form-item>

            <el-form-item label="排除路由" prop="route_exclude">
              <el-row class="msg-info">
                <el-col :span="20">输入CIDR格式如: 192.168.2.0/24</el-col>
                <el-col :span="4">
                  <el-button size="mini" type="success" icon="el-icon-plus" circle
                    @click.prevent="addDomain(ruleForm.route_exclude)"></el-button>
                </el-col>
              </el-row>
              <el-row v-for="(item, index) in ruleForm.route_exclude" :key="index" style="margin-bottom: 5px"
                :gutter="10">
                <el-col :span="10">
                  <el-input v-model="item.val"></el-input>
                </el-col>
                <el-col :span="12">
                  <el-input v-model="item.note" placeholder="备注"></el-input>
                </el-col>
                <el-col :span="2">
                  <el-button size="mini" type="danger" icon="el-icon-minus" circle
                    @click.prevent="removeDomain(ruleForm.route_exclude, index)"></el-button>
                </el-col>
              </el-row>
            </el-form-item>
          </el-tab-pane>

          <el-tab-pane label="权限控制" name="link_acl">
            <el-form-item label="权限控制" prop="link_acl">
              <el-row class="msg-info">
                <el-col :span="22">输入CIDR格式如: 192.168.3.0/24
                  协议支持 all,tcp,udp,icmp
                  端口0表示所有端口,多个端口:80,443,连续端口:1234-5678
                </el-col>
                <el-col :span="2">
                  <el-button size="mini" type="success" icon="el-icon-plus" circle
                    @click.prevent="addAclRule"></el-button>
                </el-col>
              </el-row>

              <!-- 拖拽功能 -->
              <draggable v-model="ruleForm.link_acl" handle=".drag-handle" @end="onEnd">
                <el-row v-for="(item, index) in ruleForm.link_acl" :key="index" style="margin-bottom: 5px" :gutter="1">

                  <el-col :span="1" class="drag-handle">
                    <i class="el-icon-rank"></i>
                  </el-col>

                  <el-col :span="9">
                    <el-input placeholder="请输入CIDR地址" v-model="item.val">
                      <el-select v-model="item.action" slot="prepend">
                        <el-option label="允许" value="allow"></el-option>
                        <el-option label="禁止" value="deny"></el-option>
                      </el-select>
                    </el-input>
                  </el-col>

                  <el-col :span="3">
                    <el-input placeholder="协议" v-model="item.protocol"></el-input>
                  </el-col>

                  <el-col :span="6">
                    <el-input v-model="item.port" placeholder="多端口,号分隔"></el-input>
                  </el-col>

                  <el-col :span="3">
                    <el-input v-model="item.note" placeholder="备注"></el-input>
                  </el-col>

                  <el-col :span="2">
                    <el-button size="mini" type="danger" icon="el-icon-minus" circle
                      @click.prevent="removeAclRule(index)"></el-button>
                  </el-col>
                </el-row>
              </draggable>

            </el-form-item>
          </el-tab-pane>

          <el-tab-pane label="动态拆分隧道" name="ds_domains">
            <el-form-item label="包含域名" prop="ds_include_domains">
              <el-input type="textarea" :rows="5" v-model="ruleForm.ds_include_domains"></el-input>
            </el-form-item>
            <el-form-item label="排除域名" prop="ds_exclude_domains">
              <el-input type="textarea" :rows="5" v-model="ruleForm.ds_exclude_domains"></el-input>
            </el-form-item>
          </el-tab-pane>
        </el-tabs>
        <el-form-item>
          <el-button type="primary" @click="submitForm('ruleForm')">保存</el-button>
          <el-button @click="disVisible">取消</el-button>
        </el-form-item>
      </el-form>
    </el-dialog>
  </div>

</template>

<script>
import axios from "axios";
import draggable from 'vuedraggable'

export default {
  name: "Policy",
  components: { draggable },
  mixins: [],
  created() {
    this.$emit('update:route_path', this.$route.path)
    this.$emit('update:route_name', ['用户信息', '用户策略'])
  },
  mounted() {
    this.getData(1)
  },
  data() {
    return {
      page: 1,
      tableData: [],
      count: 10,
      activeTab: "general",
      readMore: {},
      readMinRows: 5,
      ruleForm: {
        bandwidth: -1,  // 默认为-1表示使用组策略
        bandwidth_format: '',  // 默认为空
        status: 1,
        allow_lan: true,
        client_dns: [],
        route_include: [],
        route_exclude: [],
        link_acl: [],
        re_upper_limit: 0,
      },
      rules: {
        username: [
          { required: true, message: '请输入用户名', trigger: 'blur' },
          { max: 30, message: '长度小于 30 个字符', trigger: 'blur' }
        ],
        bandwidth_format: [
          {
            validator: (rule, value, callback) => {
              // 当值为空时，不验证，因为我们会将其转换为-1（使用组策略）
              if (value === '' || value === null || value === undefined) {
                callback();
                return;
              }

              // 验证是否为有效的数字且大于等于0
              const numValue = parseFloat(value);
              if (!isNaN(numValue) && numValue >= 0) {
                callback();
              } else {
                callback(new Error('带宽必须为非负数'));
              }
            },
            trigger: 'blur'
          }
        ],
        status: [
          { required: true }
        ],
      },
    }
  },
  methods: {
    handleDel(row) {
      axios.post('/user/policy/del?id=' + row.id).then(resp => {
        const rdata = resp.data;
        if (rdata.code === 0) {
          this.$message.success(rdata.msg);
          this.getData(1);
        } else {
          this.$message.error(rdata.msg);
        }
        console.log(rdata);
      }).catch(error => {
        this.$message.error('哦，请求出错');
        console.log(error);
      });
    },
    handleEdit(row) {
      !this.$refs['ruleForm'] || this.$refs['ruleForm'].resetFields();
      console.log(row)
      this.activeTab = "general"
      this.user_edit_dialog = true
      if (!row) {
        this.ruleForm.bandwidth_format = '';
        return;
      }

      axios.get('/user/policy/detail', {
        params: {
          id: row.id,
        }
      }).then(resp => {
        const data = resp.data.data;
        if (data.bandwidth === -1) {
          data.bandwidth_format = '';
        } else if (data.bandwidth === 0) {
          data.bandwidth_format = '0';
        } else {
          data.bandwidth_format = this.convertBandwidth(data.bandwidth, 'BYTE', 'Mbps').toString();
        }
        this.ruleForm = data;
      }).catch(error => {
        this.$message.error('哦，请求出错');
        console.log(error);
      });
    },
    pageChange(p) {
      this.getData(p)
    },
    getData(page) {
      this.page = page
      axios.get('/user/policy/list', {
        params: {
          page: page,
        }
      }).then(resp => {
        const rdata = resp.data.data;
        console.log(rdata);
        this.tableData = rdata.datas;
        this.count = rdata.count
      }).catch(error => {
        this.$message.error('哦，请求出错');
        console.log(error);
      });
    },
    addAclRule() {
      this.ruleForm.link_acl.push({
        protocol: "all",
        val: "",
        action: "allow",
        port: "0",
        note: ""
      });
    },
    removeAclRule(index) {
      if (index >= 0 && index < this.ruleForm.link_acl.length) {
        this.ruleForm.link_acl.splice(index, 1);
      }
    },
    onEnd() {
      window.console.log("onEnd", this.ruleForm.link_acl);
    },
    removeDomain(arr, index) {
      console.log(index)
      if (index >= 0 && index < arr.length) {
        arr.splice(index, 1)
      }
      // let index = arr.indexOf(item);
      // if (index !== -1 && arr.length > 1) {
      //   arr.splice(index, 1)
      // }
      // arr.pop()
    },
    addDomain(arr) {
      arr.push({ val: "", action: "allow", port: 0 });
    },
    convertBandwidth(bandwidth, fromUnit, toUnit) {
      const units = {
        bps: 1,
        Kbps: 1000,
        Mbps: 1000000,
        Gbps: 1000000000,
        BYTE: 8,
      };
      const result = bandwidth * units[fromUnit] / units[toUnit];
      const fixedResult = result.toFixed(2);
      return parseFloat(fixedResult);
    },
    submitForm(formName) {
      this.$refs[formName].validate((valid) => {
        if (!valid) {
          console.log('error submit!!');
          return false;
        }
        // 处理带宽限制逻辑
        if (this.ruleForm.bandwidth_format === '' || this.ruleForm.bandwidth_format === null || this.ruleForm.bandwidth_format === undefined) {
          // 如果用户没有输入值（留空），发送-1表示使用组策略
          this.ruleForm.bandwidth = -1;
        } else {
          this.ruleForm.bandwidth = this.convertBandwidth(parseFloat(this.ruleForm.bandwidth_format), 'Mbps', 'BYTE');
        } axios.post('/user/policy/set', this.ruleForm).then(resp => {
          const rdata = resp.data;
          if (rdata.code === 0) {
            this.$message.success(rdata.msg);
            this.getData(1);
            this.user_edit_dialog = false
          } else {
            this.$message.error(rdata.msg);
          }
          console.log(rdata);
        }).catch(error => {
          this.$message.error('哦，请求出错');
          console.log(error);
        });
      });
    },
    resetForm(formName) {
      this.$refs[formName].resetFields();
    },
    toggleMore(id) {
      if (this.readMore[id]) {
        this.$set(this.readMore, id, false);
      } else {
        this.$set(this.readMore, id, true);
      }
    },
    beforeTabLeave() {
      var isSwitch = true
      if (!this.user_edit_dialog) {
        return isSwitch;
      }
      this.$refs['ruleForm'].validate((valid) => {
        if (!valid) {
          this.$message.error("错误：您有必填项没有填写。")
          isSwitch = false;
          return false;
        }
      });
      return isSwitch;
    },
    closeDialog() {
      this.user_edit_dialog = false;
      this.activeTab = "general";
    },
  },

}
</script>

<style scoped>
.msg-info {
  background-color: #f4f4f5;
  color: #909399;
  padding: 0 5px;
  margin: 0;
  box-sizing: border-box;
  border-radius: 4px;
  font-size: 12px;
}

.el-select {
  width: 80px;
}

.drag-handle {
  cursor: move;
  text-align: center;
  line-height: 32px;
}
</style>
