#!/bin/bash
# build-all-platforms.sh
# 全平台编译脚本 - 适用于多文件Go项目

set -e  # 遇到错误退出

APP_NAME="cleandns"
VERSION="1.0.0"
BUILD_DIR="dist"
MAIN_PACKAGE="./"

# 需要包含在发布包中的文件
RELEASE_FILES=(
    "config.json"
    "LICENSE"
    "README.md"
)



# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查是否为模块化项目
if [ -f "go.mod" ]; then
    MODULE_NAME=$(head -n 1 go.mod | awk '{print $2}')
    info "检测到Go模块: $MODULE_NAME"
else
    warning "未找到go.mod文件，使用传统模式编译"
    MAIN_PACKAGE="."  # 回退到当前目录
fi

# 获取所有支持的平台
get_all_platforms() {
    go tool dist list
}

# 过滤不需要的平台（如需要CGO的移动平台）
filter_platforms() {
    local platforms=$1
    # 排除需要CGO或特殊SDK的平台
    echo "$platforms" | grep -v -E "^(android|ios|js|wasip1|plan9/386)"
}

# 获取编译后的可执行文件路径
get_binary_path() {
    local goos=$1
    local goarch=$2
    local goarm=${3:-}
    
    local binary_name="${APP_NAME}-${VERSION}-${goos}-${goarch}"
    
    if [ -n "$goarm" ]; then
        binary_name="${binary_name}v${goarm}"
    fi
    
    if [ "$goos" = "windows" ]; then
        binary_name="${binary_name}.exe"
    fi
    
    echo "${BUILD_DIR}/${binary_name}"
}

# 创建发布包目录结构
create_release_package() {
    local goos=$1
    local goarch=$2
    local goarm=${3:-}
    
    # 构建目录名
    local package_name="${APP_NAME}-${VERSION}-${goos}-${goarch}"
    if [ -n "$goarm" ]; then
        package_name="${package_name}v${goarm}"
    fi
    
    local package_dir="${BUILD_DIR}/packages/${package_name}"
    
    # 创建目录
    mkdir -p "$package_dir"
    
    # 复制所需文件
    info "   创建发布包: $package_name"
    
    # 获取可执行文件在构建目录中的路径
    local binary_path=$(get_binary_path "$goos" "$goarch" "$goarm")
    
    # 确定目标文件名
    local target_binary_name="$APP_NAME"
    if [ "$goos" = "windows" ]; then
        target_binary_name="${APP_NAME}.exe"
    fi
    
    if [ -f "$binary_path" ]; then
        cp "$binary_path" "$package_dir/$target_binary_name"
        success "     已复制可执行文件: $(basename "$binary_path") -> $target_binary_name"
    else
        warning "     可执行文件不存在: $binary_path"
        return 1
    fi
    
    # 复制其他文件
    for file in "${RELEASE_FILES[@]}"; do
        if [ -f "$file" ]; then
            cp "$file" "$package_dir/"
            info "     已复制: $file"
        else
            warning "     文件不存在，跳过: $file"
        fi
    done
    
    # 如果存在docs目录，可以一并复制
    if [ -d "docs" ]; then
        cp -r docs "$package_dir/" 2>/dev/null || true
        info "     已复制文档目录"
    fi
    
    # 如果存在config目录，可以一并复制
    if [ -d "configs" ]; then
        cp -r configs "$package_dir/" 2>/dev/null || true
        info "     已复制配置目录"
    fi
    
    # 创建tar.gz压缩包
    info "   创建压缩包: ${package_name}.tar.gz"
    pushd "${BUILD_DIR}/packages" >/dev/null
    tar -czf "${package_name}.tar.gz" "$package_name"
    popd >/dev/null
    
    success "   发布包创建完成: ${package_name}.tar.gz"
    return 0
}

# 编译单个平台
compile_platform() {
    local goos=$1
    local goarch=$2
    
    info "编译: ${goos}/${goarch}"
    
    # 设置环境变量并编译
    if [ "$goarch" = "arm" ]; then
        # ARM架构需要指定GOARM
        for goarm in 5 6 7; do
            local binary_path=$(get_binary_path "$goos" "$goarch" "$goarm")
            
            info "  子架构: ARMv${goarm}"
            if ! GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 \
                 go build -trimpath \
                 -ldflags="-s -w -X main.Version=${VERSION}" \
                 -o "$binary_path" "$MAIN_PACKAGE"; then
                warning "  编译失败: ${goos}/${goarch}v${goarm}"
            else
                success "  编译成功: $(basename "$binary_path")"
                # 创建发布包
                create_release_package "$goos" "$goarch" "$goarm"
            fi
        done
    else
        # 其他架构
        local binary_path=$(get_binary_path "$goos" "$goarch")
        
        if ! GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
             go build -trimpath \
             -ldflags="-s -w -X main.Version=${VERSION}" \
             -o "$binary_path" "$MAIN_PACKAGE"; then
            warning "编译失败: ${goos}/${goarch}"
            return 1
        else
            success "编译成功: $(basename "$binary_path")"
            # 创建发布包
            create_release_package "$goos" "$goarch"
        fi
    fi
    
    return 0
}

# 检查依赖并下载
check_dependencies() {
    info "检查Go依赖..."
    
    # 检查是否在模块化项目中
    if [ -f "go.mod" ]; then
        info "下载模块依赖..."
        go mod download
        
        info "检查vendored依赖..."
        if [ -d "vendor" ]; then
            info "使用vendor目录中的依赖"
        else
            info "使用Go模块缓存"
        fi
    else
        info "非模块化项目，使用GOPATH模式"
        # 检查是否设置了GOPATH
        if [ -z "$GOPATH" ]; then
            warning "GOPATH未设置，可能需要手动设置"
        fi
    fi
    
    # 检查必要的工具
    info "检查构建工具..."
    if ! command -v go >/dev/null 2>&1; then
        error "未找到Go编译器"
        exit 1
    fi
    
    # 检查UPX（可选）
    if command -v upx >/dev/null 2>&1; then
        info "UPX已安装"
    else
        warning "UPX未安装，跳过二进制压缩"
    fi
}

# 压缩可执行文件（如果安装了upx）
compress_binary() {
    if command -v upx >/dev/null 2>&1; then
        info "使用UPX压缩可执行文件..."
        find "$BUILD_DIR" -maxdepth 1 -type f \( -name "*.exe" -o ! -name "*.*" \) \
             -exec upx --best --lzma {} \; 2>/dev/null || true
    else
        warning "未找到UPX，跳过压缩"
    fi
}

# 生成SHA256校验和
generate_checksums() {
    info "生成SHA256校验和..."
    
    # 为所有压缩包生成校验和
    if [ -d "${BUILD_DIR}/packages" ]; then
        pushd "${BUILD_DIR}/packages" >/dev/null
        if command -v shasum >/dev/null 2>&1; then
            shasum -a 256 -- *.tar.gz > "SHA256SUMS.txt" 2>/dev/null
        elif command -v sha256sum >/dev/null 2>&1; then
            sha256sum -- *.tar.gz > "SHA256SUMS.txt" 2>/dev/null
        else
            warning "未找到sha256sum或shasum命令"
        fi
        popd >/dev/null
    fi
    
    # 为原始可执行文件生成校验和
    pushd "$BUILD_DIR" >/dev/null
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- *[^.gz][^.txt] 2>/dev/null > "SHA256SUMS-binaries.txt" || true
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- *[^.gz][^.txt] 2>/dev/null > "SHA256SUMS-binaries.txt" || true
    fi
    popd >/dev/null
}

# 生成构建报告
generate_report() {
    info "生成构建报告..."
    local report_file="${BUILD_DIR}/build-report.txt"
    {
        echo "构建报告 - ${APP_NAME} v${VERSION}"
        echo "构建时间: $(date)"
        echo "Go版本: $(go version)"
        echo "系统信息: $(uname -a)"
        echo "构建模式: $(if [ -f "go.mod" ]; then echo "模块化项目"; else echo "传统GOPATH项目"; fi)"
        echo "主包路径: ${MAIN_PACKAGE}"
        echo "======================================"
        echo "编译的文件:"
        echo "======================================"
        find "$BUILD_DIR" -maxdepth 1 -type f \( -name "*.exe" -o ! -name "*.*" \) \
             -exec basename {} \; | sort
        
        echo ""
        echo "打包的文件:"
        echo "======================================"
        if [ -d "${BUILD_DIR}/packages" ]; then
            find "${BUILD_DIR}/packages" -name "*.tar.gz" -exec basename {} \; | sort
        fi
        
        echo ""
        echo "文件详细信息:"
        echo "======================================"
        echo "原始文件:"
        ls -lh "$BUILD_DIR"
        
        if [ -d "${BUILD_DIR}/packages" ]; then
            echo ""
            echo "打包文件:"
            ls -lh "${BUILD_DIR}/packages"
        fi
    } > "$report_file"
}

# 清理临时文件
cleanup_temp_dirs() {
    info "清理临时目录..."
    if [ -d "${BUILD_DIR}/packages" ]; then
        # 删除所有临时目录，只保留tar.gz文件
        find "${BUILD_DIR}/packages" -type d -name "${APP_NAME}-*" -exec rm -rf {} \; 2>/dev/null || true
        success "临时目录已清理"
    fi
}

# 构建当前平台
build_current_platform() {
    info "构建当前平台..."
    
    local goos=$(go env GOOS)
    local goarch=$(go env GOARCH)
    local binary_name="${APP_NAME}"
    
    if [ "$goos" = "windows" ]; then
        binary_name="${binary_name}.exe"
    fi
    
    if ! go build -trimpath \
         -ldflags="-s -w -X main.Version=${VERSION}" \
         -o "$binary_name" "$MAIN_PACKAGE"; then
        error "当前平台构建失败"
        return 1
    else
        success "当前平台构建成功: $binary_name"
        
        # 复制到构建目录
        cp "$binary_name" "${BUILD_DIR}/"
        
        # 创建当前平台的发布包
        create_release_package "$goos" "$goarch"
        
        return 0
    fi
}

# 主函数
main() {
    info "开始全平台编译: ${APP_NAME} v${VERSION}"
    
    # 检查依赖
    check_dependencies
    
    # 检查主包
    if [ ! -d "$(dirname "$MAIN_PACKAGE")" ] && [ "$MAIN_PACKAGE" != "." ]; then
        error "主包目录不存在: $(dirname "$MAIN_PACKAGE")"
        error "请设置正确的MAIN_PACKAGE变量"
        exit 1
    fi
    
    # 检查必要的发布文件
    info "检查发布文件..."
    for file in "${RELEASE_FILES[@]}"; do
        if [ -f "$file" ]; then
            info "  ✓ $file"
        else
            warning "  ✗ 文件不存在: $file"
        fi
    done
    
    # 清理并创建构建目录
    info "清理构建目录: ${BUILD_DIR}"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    mkdir -p "${BUILD_DIR}/packages"
    
    # 获取并过滤平台列表
    info "获取支持的平台列表..."
    all_platforms=$(get_all_platforms)
    filtered_platforms=$(filter_platforms "$all_platforms")
    
    total=$(echo "$filtered_platforms" | wc -l | tr -d ' ')
    info "将尝试编译 ${total} 个平台"
    
    success_count=0
    fail_count=0
    
    # 遍历所有平台进行编译
    while IFS= read -r platform; do
        if [ -z "$platform" ]; then
            continue
        fi
        
        goos="${platform%%/*}"
        goarch="${platform##*/}"
        
        if compile_platform "$goos" "$goarch"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
    done <<< "$filtered_platforms"
    
    # 后处理
    compress_binary
    generate_checksums
    generate_report
    cleanup_temp_dirs
    
    # 统计结果
    echo ""
    info "========== 构建完成 =========="
    info "成功: ${success_count} 个平台"
    info "失败: ${fail_count} 个平台"
    info "总计: ${total} 个平台"
    
    if [ -d "${BUILD_DIR}/packages" ]; then
        local package_count=$(find "${BUILD_DIR}/packages" -name "*.tar.gz" | wc -l)
        info "生成发布包: ${package_count} 个"
    fi
    
    info "输出目录结构:"
    echo ""
    find "$BUILD_DIR" -type f -name "*.txt" -o -name "*.tar.gz" | sort | sed "s|^${BUILD_DIR}/||"
    echo ""
    
    # 显示文件列表
    info "详细文件列表:"
    ls -lh "${BUILD_DIR}"
    if [ -d "${BUILD_DIR}/packages" ]; then
        ls -lh "${BUILD_DIR}/packages"
    fi
}

# 处理命令行参数
case "${1:-}" in
    "--current"|"-c")
        # 只构建当前平台
        check_dependencies
        rm -rf "$BUILD_DIR"
        mkdir -p "$BUILD_DIR"
        mkdir -p "${BUILD_DIR}/packages"
        build_current_platform
        generate_checksums
        generate_report
        cleanup_temp_dirs
        ;;
    "--help"|"-h")
        echo "用法: $0 [选项]"
        echo ""
        echo "选项:"
        echo "  -c, --current    只构建当前平台"
        echo "  -h, --help       显示此帮助信息"
        echo "  无参数           构建所有支持的平台"
        ;;
    *)
        # 默认构建所有平台
        main "$@"
        ;;
esac