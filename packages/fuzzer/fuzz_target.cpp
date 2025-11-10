// http_fuzzer_mutate.cpp
// Compile with LibFuzzer:
// clang++ -std=c++17 http_fuzzer_mutate.cpp -o http_fuzzer -fsanitize=fuzzer,address,undefined -O2 -g

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <chrono>
#include <fstream>  

namespace fs = std::filesystem;

/* ---------- LibFuzzer 提供的自定义 mutator 入口声明 ---------- */
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

/* ---------- 工具：URL encode（对 key 与 value 单独使用） ---------- */
static std::string url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (unsigned char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            escaped << c;
        else {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << int(c);
        }
    }
    return escaped.str();
}

/* ---------- 解析三段：第 0 段 = 请求行/查询  1:headers 2:body ---------- */
struct HttpTriplet {
    std::string seg[3];   // 0:请求行/查询  1:headers  2:body
};

static HttpTriplet parse3(const uint8_t *d, size_t len) {
    HttpTriplet t;
    const char *p = reinterpret_cast<const char*>(d);
    const char *end = p + len;
    for (int i = 0; i < 2 && p < end; ++i) {
        const char *z = reinterpret_cast<const char*>(memchr(p, 0, end - p));
        if (!z) z = end;
        t.seg[i].assign(p, z - p);
        p = z;
        if (p < end) ++p; // skip the NUL
    }
    if (p < end) t.seg[2].assign(p, end - p);
    return t;
}

static std::string serialize3(const HttpTriplet &t) {
    std::string s;
    for (int i = 0; i < 3; ++i) {
        s += t.seg[i];
        if (i < 2) s.push_back(0);
    }
    return s;
}

/* ---------- JPEG 字典定义 ---------- */
static const char *kJpegDict[] = {
    "header_jfif=JFIF\x00",
    "header_jfxx=JFXX\x00",
    "section_ffc0=\xff\xc0",
    "section_ffc2=\xff\xc2",
    "section_ffc4=\xff\xc4",
    "section_ffd0=\xff\xd0",
    "section_ffd8=\xff\xd8",
    "section_ffd9=\xff\xd9",
    "section_ffda=\xff\xda",
    "section_ffdb=\xff\xdb",
    "section_ffdd=\xff\xdd",
    "section_ffe0=\xff\xe0",
    "section_ffe1=\xff\xe1",
    "section_fffe=\xff\xfe"
};
static constexpr size_t kJpegDictCnt = sizeof(kJpegDict) / sizeof(kJpegDict[0]);

/* ---------- 辅助：把请求行拆成 three parts：
pre  = method + ' '  （包含第一个空格）
pathq = path[?query]  （中间部分）
suf  = ' ' + rest (HTTP/version... 或空)
如果解析失败，则 pre="" pathq=原始 suf=""
*/
static void split_request_line(const std::string &line,
    std::string &pre, std::string &pathq, std::string &suf) {
    pre.clear(); pathq.clear(); suf.clear();
    // 找到第一个空格和第二个空格
    size_t p1 = line.find(' ');
    if (p1 == std::string::npos) {
        // 无空格，视作整个是 path
        pathq = line;
        return;
    }
    size_t p2 = line.find(' ', p1 + 1);
    if (p2 == std::string::npos) {
        // 只有一个空格，仍然尝试划分
        pre = line.substr(0, p1 + 1); // 包含空格
        pathq = line.substr(p1 + 1);
        return;
    }
    pre = line.substr(0, p1 + 1);
    pathq = line.substr(p1 + 1, p2 - (p1 + 1));
    suf = line.substr(p2); // 包含空格
}

/* ---------- 辅助：从 pathq（可能包含 ?query）中取出 query 部分（不含 '?'） ---------- */
static std::string extract_query(const std::string &pathq) {
    size_t qpos = pathq.find('?');
    if (qpos == std::string::npos) return std::string();
    return pathq.substr(qpos + 1);
}

/* ---------- 辅助：把 pathq 与新 query 合并（如果 newq 为空则返回原 pathq） ---------- */
static std::string replace_or_append_query(const std::string &pathq, const std::string &appended) {
    // appended 假定不包含 leading '?' 或 '&'，只是像 "k=v&x=y"（但可以为空）
    if (appended.empty()) return pathq;
    size_t qpos = pathq.find('?');
    if (qpos == std::string::npos) {
        // no existing query
        return pathq + "?" + appended;
    } else {
        std::string base = pathq;
        std::string current_query = pathq.substr(qpos + 1);
        if (!current_query.empty() && !appended.empty()) {
             base = pathq + "&" + appended;
        } else {
            base = pathq.substr(0, qpos + 1) + current_query + appended;
        }
        return base;
    }
}


/* ---------- 辅助：把 query 按 '&' 分割为 vector（空项会被忽略） ---------- */
static std::vector<std::string> split_query_params(const std::string &q) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start < q.size()) {
        size_t end = q.find('&', start);
        if (end == std::string::npos) end = q.size();
        if (end > start) out.push_back(q.substr(start, end - start));
        start = end + 1;
    }
    return out;
}

/* ---------- 通用变异：在 buffer 上进行多种字节级变异（非 bit-level） ---------- */
static void mutate_buffer_stdlib(std::vector<uint8_t> &buf, std::mt19937 &rng) {
    if (buf.empty()) {
        // If buffer is empty, try to add some initial data, e.g., a simple GET request
        if ((rng() % 2) == 0) {
            std::string initial_data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            buf.assign(initial_data.begin(), initial_data.end());
        }
        return;
    }

    std::uniform_int_distribution<int> opdist(0, 7);
    int ops = 1 + (opdist(rng) % 5); // 执行 1..5 次不同变异
    constexpr size_t MAX_BUF_SIZE = 65536;

    for (int i = 0; i < ops; ++i) {
        if (buf.empty()) {
            if ((rng() % 2) == 0) { // Try to re-seed an empty buffer
                std::string initial_data = "GET / HTTP/1.1\x00Host: example.com\x00\x00"; // NUL-separated
                buf.assign(initial_data.begin(), initial_data.end());
            } else {
                continue; // Can't mutate empty buffer further
            }
        }
        std::uniform_int_distribution<size_t> index_dist(0, buf.size() - 1);


        int op = opdist(rng);
        if (op == 0) {
            // 随机替换若干字节
            size_t pos = index_dist(rng);
            size_t len = 1 + (rng() % std::min<size_t>(16, buf.size() - pos));
            for (size_t j = 0; j < len; ++j)
                buf[pos + j] = static_cast<uint8_t>(rng() & 0xFF);
        } else if (op == 1) {
            // 随机插入少量字节（最多 32）
            size_t pos = index_dist(rng);
            size_t ins = 1 + (rng() % 32);
            if (buf.size() + ins > MAX_BUF_SIZE) continue; // 避免过大
            std::vector<uint8_t> tmp;
            tmp.reserve(buf.size() + ins);
            tmp.insert(tmp.end(), buf.begin(), buf.begin() + pos);
            for (size_t k = 0; k < ins; ++k) tmp.push_back(static_cast<uint8_t>(rng() & 0xFF));
            tmp.insert(tmp.end(), buf.begin() + pos, buf.end());
            buf.swap(tmp);
        } else if (op == 2) {
            // 随机删除一段（最多 32）
            if (buf.size() <= 1) continue;
            size_t pos = index_dist(rng);
            size_t del = 1 + (rng() % std::min<size_t>(32, buf.size() - pos));
            buf.erase(buf.begin() + pos, buf.begin() + pos + del);
        } else if (op == 3) {
            // 复制一小段到另一位置（dup）
            size_t pos = index_dist(rng);
            size_t len = 1 + (rng() % std::min<size_t>(32, buf.size() - pos));
            std::vector<uint8_t> segment(buf.begin() + pos, buf.begin() + pos + len);
            size_t insert_pos = index_dist(rng);
            if (buf.size() + segment.size() <= MAX_BUF_SIZE) {
                buf.insert(buf.begin() + insert_pos, segment.begin(), segment.end());
            }
        } else if (op == 4) {
            // XOR 一段
            size_t pos = index_dist(rng);
            size_t len = 1 + (rng() % std::min<size_t>(64, buf.size() - pos));
            uint8_t key = static_cast<uint8_t>((rng() >> 8) & 0xFF);
            for (size_t j = 0; j < len; ++j) buf[pos + j] ^= key;
        } else if (op == 5) {
            // 注入 JPEG 字典条目（随机选一个）
            size_t dict_idx = rng() % kJpegDictCnt;
            const char *s = kJpegDict[dict_idx];
            size_t slen = std::strlen(s);
            size_t pos = index_dist(rng);
            if (buf.size() + slen <= MAX_BUF_SIZE) {
                buf.insert(buf.begin() + pos, s, s + slen);
            }
        } else if (op == 6) {
            // 对 parse3 的 0 段（请求行/pathq）做 URL-encode 或追加 param
            HttpTriplet t = parse3(buf.data(), buf.size());
            if (!t.seg[0].empty()) {
                std::string pre, pathq, suf;
                split_request_line(t.seg[0], pre, pathq, suf);
                if (!pathq.empty()) {
                    // 随机选择：URL-encode pathq 的一小段，或追加随机 param
                    if ((rng() % 2) == 0) {
                        // url-encode a small substring
                        size_t from = (pathq.size() > 0) ? (rng() % pathq.size()) : 0;
                        size_t len = std::min<size_t>(pathq.size() - from, 6 + (rng() % 10));
                        std::string sub = pathq.substr(from, len);
                        std::string enc = url_encode(sub);
                        pathq.replace(from, len, enc);
                        t.seg[0] = pre + pathq + suf;
                        std::string s2 = serialize3(t);
                        // Make sure the new size doesn't exceed MAX_BUF_SIZE
                        if (s2.size() <= MAX_BUF_SIZE) {
                            buf.assign(s2.begin(), s2.end());
                        }
                    } else {
                        // append param
                        std::string addon = "fuzz_key=" + std::to_string(rng());
                        std::string newpath = replace_or_append_query(pathq, addon);
                        t.seg[0] = pre + newpath + suf;
                        std::string s2 = serialize3(t);
                        if (s2.size() <= MAX_BUF_SIZE) {
                            buf.assign(s2.begin(), s2.end());
                        }
                    }
                }
            }
        } else if (op == 7) { // 随机添加或修改 NUL 分隔符
            size_t pos = index_dist(rng);
            if (buf[pos] == 0) { // If it's already NUL, change it
                buf[pos] = static_cast<uint8_t>(rng() % 255 + 1); // any non-NUL byte
            } else { // If not NUL, insert a NUL
                if (buf.size() + 1 <= MAX_BUF_SIZE) {
                    buf.insert(buf.begin() + pos, 0);
                }
            }
        }
    }
}

/* ---------- extras 字典（用于 http_dictionary_havoc_stage） ---------- */
static const char *extras[] = {
    "debug=1",
    "admin=1",
    "auth=none",
    "format=json",
    "page=99999",
    "limit=0",
    "sort=-id",
    "token=AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "id=1' OR '1'='1",
    "q=%3Cscript%3Ealert(1)%3C/script%3E",
    "name=../../etc/passwd",
    "file=/proc/self/environ",
    "class=../../../../../../etc/passwd",
    "mode=unicode",
    "search=%00",
    "cmd=ls",
    "debug_mode=true",
    "lang=../../../../",
    "session=0",
    "X-Forwarded-For: 127.0.0.1",
    "User-Agent: Fuzzer/1.0",
    "Content-Type: application/x-www-form-urlencoded",
    "Accept-Language: en-US,en;q=0.5",
    "Cookie: JSESSIONID=fuzz_session",
    "Referer: http://fuzz.example.com",
    "Authorization: Basic Zm9vOmJhcg==",
    "Host: localhost",
    "Connection: keep-alive"
};
static constexpr size_t extras_cnt = sizeof(extras) / sizeof(extras[0]);

/* ---------- helper: 判断段是否可能是请求行（简单启发式） ---------- */
static bool likely_request_line(const std::string &s) {
    if (s.empty()) return false;
    // 常见 method 开头
    static const char *methods[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"};
    for (auto m : methods) {
        if (s.rfind(m, 0) == 0) return true; // startswith
    }
    // 或包含 HTTP/
    if (s.find("HTTP/") != std::string::npos) return true;
    return false;
}

/* ---------- http_dictionary_havoc_stage ----------
   从 extras[] 随机挑若干条，拼成 add_on（以 & 开头），插入到输入中的若干 NUL 分段（常对应 query/cookie/body）
   - in_buf: 原始数据（NUL 分段）
   - rng: 随机数
   返回 vector<bytes>：一组变异后生成的缓冲区（以便后续送入 target）
*/
static std::vector<std::vector<uint8_t>> http_dictionary_havoc_stage(
    const std::vector<uint8_t> &in_buf, std::mt19937 &rng, size_t tries = 5) {

    std::vector<std::vector<uint8_t>> results;
    if (in_buf.empty()) return results;

    // 将 in_buf 按 NUL 分段
    std::vector<std::string> parts;
    {
        const char *p = reinterpret_cast<const char *>(in_buf.data());
        size_t len = in_buf.size();
        size_t pos = 0;
        while (pos < len) {
            const char *z = reinterpret_cast<const char*>(memchr(p + pos, 0, len - pos));
            if (!z) {
                parts.emplace_back(p + pos, len - pos);
                break;
            } else {
                size_t seglen = z - (p + pos);
                parts.emplace_back(p + pos, seglen);
                pos += seglen + 1;
            }
        }
        if (parts.empty() && !in_buf.empty()) { // Handle case where input has no NULs
            parts.emplace_back(reinterpret_cast<const char *>(in_buf.data()), in_buf.size());
        }
    }

    if (parts.empty()) return results; // No parts to mutate

    std::uniform_int_distribution<size_t> extras_count_dist(1, 4);
    std::uniform_int_distribution<size_t> which_part(0, parts.size() - 1);
    constexpr size_t MAX_BUF_SIZE = 65536;

    for (size_t t = 0; t < tries; ++t) {
        size_t take = extras_count_dist(rng);
        std::string add_on_prefix;
        std::string add_on_data;
        // 随机决定是追加到 query 还是 headers/body
        if ((rng() % 3) == 0) { // Add to query
            add_on_prefix = "&";
        } else if ((rng() % 3) == 1) { // Add to headers
            add_on_prefix = "\r\n";
        } else { // Add to body or other segments
            add_on_prefix = " "; // Space or no prefix
        }

        for (size_t i = 0; i < take; ++i) {
            const char *e = extras[rng() % extras_cnt];
            if (!add_on_data.empty() && add_on_prefix == "&" && e[0] != '&') add_on_data.push_back('&');
            if (!add_on_data.empty() && add_on_prefix == "\r\n" && !(e[0] == '\r' && e[1] == '\n')) add_on_data.append("\r\n");
            
            // For query-like extras, URL-encode if needed
            if (add_on_prefix == "&") {
                std::string param_str = e;
                size_t eq_pos = param_str.find('=');
                if (eq_pos != std::string::npos) {
                    add_on_data += url_encode(param_str.substr(0, eq_pos)) + "=" + url_encode(param_str.substr(eq_pos + 1));
                } else {
                    add_on_data += url_encode(param_str);
                }
            } else {
                add_on_data += e;
            }
        }

        // Decide how many positions to insert the add_on
        size_t inserts = 1 + (rng() % std::max<size_t>(1, parts.size()));
        std::vector<std::string> newparts = parts;
        bool inserted = false;

        for (size_t ins = 0; ins < inserts; ++ins) {
            size_t pidx = which_part(rng);
            if (pidx >= newparts.size()) pidx = 0; // Fallback for small parts vector

            // Target part could be request line (needs intelligent merging to pathq), or normal segment (direct append/insert)
            if (likely_request_line(newparts[pidx])) {
                std::string pre, pathq, suf;
                split_request_line(newparts[pidx], pre, pathq, suf);
                if (!pathq.empty()) {
                    // Remove leading '&' if add_on_prefix was meant for query,
                    // as replace_or_append_query will handle the '?'/'&'
                    std::string to_add = add_on_data;
                    if (!to_add.empty() && to_add.front() == '&') to_add.erase(to_add.begin());
                    
                    std::string newpath = replace_or_append_query(pathq, to_add);
                    newparts[pidx] = pre + newpath + suf;
                    inserted = true;
                } else {
                    // If no pathq, fall through to direct insertion or append
                    size_t pos = (newparts[pidx].empty()) ? 0 : (rng() % (newparts[pidx].size() + 1));
                    newparts[pidx].insert(pos, add_on_prefix + add_on_data);
                    inserted = true;
                }
            } else {
                // For other segments (headers, body, cookies), directly insert
                size_t pos = (newparts[pidx].empty()) ? 0 : (rng() % (newparts[pidx].size() + 1));
                newparts[pidx].insert(pos, add_on_prefix + add_on_data);
                inserted = true;
            }
        }
        
        if (!inserted && !newparts.empty()) { // Ensure at least one insertion happened if possible
            // If no intelligent insertion path, just append to a random part
            size_t pidx = rng() % newparts.size();
            newparts[pidx] += add_on_prefix + add_on_data;
        }


        // serialize back into buffer with NUL separators
        std::vector<uint8_t> out;
        out.reserve(in_buf.size() + add_on_data.size() * inserts); // Pre-reserve to avoid reallocations
        for (size_t i = 0; i < newparts.size(); ++i) {
            if (out.size() + newparts[i].size() > MAX_BUF_SIZE) break; // Prevent buffer explosion
            out.insert(out.end(), newparts[i].begin(), newparts[i].end());
            if (i + 1 < newparts.size()) {
                 if (out.size() + 1 > MAX_BUF_SIZE) break;
                 out.push_back(0);
            }
        }
        if (!out.empty()) { // Only add if successfully mutated and not empty
            results.push_back(std::move(out));
        }
    }

    return results;
}

/* ---------- http_queue_var_combine_stage ----------
   - Stage 1a (单变量与 out_buf 组合): 对当前 out_buf 把 vars 中每个 var 追加到 URL query 中，生成多个候选。
   - Stage 1b (单变量与队列中的每个文件组合): 对队列 queue 每个文件，若其第0段是请求行/URL，则把 vars 中每个 var 添加到该 URL 生成新的 buffer。
   参数:
    - in_buf: 当前输入
    - vars: 要添加的名值对（如 GETS）
    - queue_bufs: "队列"中的其他已知缓冲区（通常来自磁盘或历史输入），以 vector<string> 表示（每个为 raw bytes）
   返回: 生成的变异缓冲区列表
*/
static std::vector<std::vector<uint8_t>> http_queue_var_combine_stage(
    const std::vector<uint8_t> &in_buf,
    const std::vector<std::string> &vars,
    const std::vector<std::vector<uint8_t>> &queue_bufs,
    std::mt19937 &rng) {

    std::vector<std::vector<uint8_t>> results;

    if (vars.empty()) return results;

    constexpr size_t MAX_BUF_SIZE = 65536;

    // Helper to process a buffer and add vars to its query
    auto process_buf_with_vars = [&](const std::vector<uint8_t>& buf_to_process) {
        if (buf_to_process.empty()) return;

        HttpTriplet t = parse3(buf_to_process.data(), buf_to_process.size());
        if (!t.seg[0].empty() && likely_request_line(t.seg[0])) {
            std::string pre, pathq, suf;
            split_request_line(t.seg[0], pre, pathq, suf);
            if (!pathq.empty()) {
                for (const auto &v : vars) {
                    // v 假定是 "k=v" 格式或 "k=" 等
                    std::string addon_key;
                    std::string addon_val;
                    size_t eq = v.find('=');
                    if (eq != std::string::npos) {
                        addon_key = v.substr(0, eq);
                        addon_val = v.substr(eq + 1);
                    } else {
                        addon_key = v;
                    }
                    
                    std::string encoded_addon = url_encode(addon_key);
                    if (!addon_val.empty()) {
                        encoded_addon += "=" + url_encode(addon_val);
                    }

                    std::string newpath = replace_or_append_query(pathq, encoded_addon);
                    HttpTriplet t2 = t;
                    t2.seg[0] = pre + newpath + suf;
                    std::string s2 = serialize3(t2);
                    if (s2.size() <= MAX_BUF_SIZE) {
                        std::vector<uint8_t> out(s2.begin(), s2.end());
                        results.push_back(std::move(out));
                    }
                }
            }
        }
    };

    // Stage 1a: 单变量与 in_buf 组合
    process_buf_with_vars(in_buf);

    // Stage 1b: 单变量与队列中每个文件组合
    for (const auto &qbuf : queue_bufs) {
        // Skip if qbuf is the same as in_buf (to avoid duplicate work or if `queue_bufs` contains `in_buf`)
        if (qbuf == in_buf) continue;
        process_buf_with_vars(qbuf);
    }

    return results;
}

/* ---------- simulate_target ----------
   占位函数：这里应该调用真正的被测函数 / harness target。
   作为示例，我们只是做一些无害的字符串检查，避免优化掉整个函数。
*/
static void simulate_target(const uint8_t *data, size_t size) {
    // 这是一个模拟的目标函数。
    // 在实际的Fuzzing中，你会在这里调用你的HTTP库或应用程序的解析/处理函数。
    // 例如：
    // my_http_parser_parse(data, size);
    // my_http_server_handle_request(data, size);
    
    // 做一些“无法被编译器轻易优化掉”的检查/副作用
    volatile uint32_t acc = 0;
    for (size_t i = 0; i + 4 <= size; i += 4) {
        uint32_t v = (static_cast<uint32_t>(data[i]) << 24) |
                     (static_cast<uint32_t>(data[i+1]) << 16) |
                     (static_cast<uint32_t>(data[i+2]) << 8) |
                     (static_cast<uint32_t>(data[i+3]));
        acc ^= v;
    }
    // 避免编译器优化掉对 acc 的写入
    if (size > 0 && data[0] == 'G') {
        volatile int x = data[0]; // Some random side effect
    }
    // Parse the HTTP triplet, just for some processing
    HttpTriplet t = parse3(data, size);
    (void)t; // Use t to prevent unused variable warning
}

/* ---------- 辅助：从 in_buf 中收集可能的 vars（GETS/POSTS/COOKIES）简易启发式实现
   - 对 headers/body 中形如 "k=v" 或 "k: v" 的字符串进行抓取（极其简单的启发式）
*/
static std::vector<std::string> extract_candidate_vars(const std::vector<uint8_t> &in_buf) {
    std::vector<std::string> out;
    if (in_buf.empty()) return out;

    std::string s(reinterpret_cast<const char*>(in_buf.data()), in_buf.size());
    // Try to extract from query string part if it exists
    HttpTriplet t = parse3(in_buf.data(), in_buf.size());
    if (!t.seg[0].empty()) {
        std::string pre, pathq, suf;
        split_request_line(t.seg[0], pre, pathq, suf);
        if (!pathq.empty()) {
            std::string query = extract_query(pathq);
            if (!query.empty()) {
                std::vector<std::string> query_params = split_query_params(query);
                out.insert(out.end(), query_params.begin(), query_params.end());
            }
        }
    }

    // Also look for k=v or k:v patterns in headers and body
    size_t pos = 0;
    while (pos < s.size()) {
        size_t next_line = s.find_first_of("\r\n", pos);
        if (next_line == std::string::npos) next_line = s.size();

        std::string line = s.substr(pos, next_line - pos);
        
        // Look for "key=value" (form data, query, cookies)
        size_t eq_pos = line.find('=');
        if (eq_pos != std::string::npos && eq_pos > 0 && eq_pos < line.size() - 1) {
             out.push_back(line.substr(0, eq_pos + 1) + line.substr(eq_pos + 1));
        }

        // Look for "Key: Value" (headers)
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos && colon_pos > 0 && colon_pos < line.size() - 1) {
            // Trim spaces around colon
            size_t key_end = colon_pos;
            while(key_end > 0 && std::isspace(static_cast<unsigned char>(line[key_end - 1]))) key_end--;
            size_t val_start = colon_pos + 1;
            while(val_start < line.size() && std::isspace(static_cast<unsigned char>(line[val_start]))) val_start++;
            
            if (key_end > 0 && val_start < line.size()) {
                out.push_back(line.substr(0, key_end) + "=" + line.substr(val_start));
            }
        }

        if (next_line == s.size()) break;
        pos = next_line + 1;
        if (pos < s.size() && s[pos] == '\n') pos++; // Handle CRLF
    }
  
    // Clean and unique
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    
    return out;
}

/* ---------- 辅助：把 vector<uint8_t> 转为 hex/preview，用于 debug（可选） ---------- */
// static std::string preview_buf(const std::vector<uint8_t> &b, size_t maxlen = 128) {
//     std::ostringstream os;
//     size_t len = std::min(maxlen, b.size());
//     for (size_t i = 0; i < len; ++i) {
//         char c = static_cast<char>(b[i]);
//         if (std::isprint(static_cast<unsigned char>(c))) os << c;
//         else os << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)c << std::dec;
//     }
//     if (b.size() > len) os << "...";
//     return os.str();
// }


/* ---------- LLVMFuzzerTestOneInput：LibFuzzer 入口，执行目标函数 ---------- */
// 这是一个 Fuzzer "harness" 的核心。它接收 fuzzer 生成的输入数据，并将其传递给被测试的代码。
// 这里不应该进行变异，变异由 LLVMFuzzerMutate 或 LibFuzzer 内部完成。
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data || Size == 0) {
        // LibFuzzer might provide empty inputs. Handle them gracefully.
        return 0;
    }

    // 调用您的目标函数 (harness)
    simulate_target(Data, Size);

    return 0; // 0 表示成功执行。非零值可能表示一个 crash (通常由 Sanitizer 捕获)
}


/* ---------- LLVMFuzzerMutate：自定义变异器入口 ---------- */
// 这个函数由 LibFuzzer 调用，用于对当前输入进行自定义变异。
// 它应该接收 Data 和 Size，在 MaxSize 范围内进行变异，然后返回新的 Size。
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
    // 如果没有输入，或者 Size 超过了 MaxSize，则不能变异
    if (Size == 0 || Size > MaxSize) return 0;
    std::mt19937 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count());

    std::vector<uint8_t> current_buffer_vec(Data, Data + Size);
    std::vector<uint8_t> mutated_buffer;

    // 随机选择一种变异策略
    // 0: 通用字节级变异
    // 1: HTTP 字典注入
    // 2: HTTP 变量组合
    std::uniform_int_distribution<int> strategy_dist(0, 2); 
    int strategy = strategy_dist(rng);

    if (strategy == 0) {
        // 应用通用字节级变异
        mutated_buffer = current_buffer_vec; 
        mutate_buffer_stdlib(mutated_buffer, rng);
    } else if (strategy == 1) {
        // 应用 HTTP 字典注入变异
        auto dict_results = http_dictionary_havoc_stage(current_buffer_vec, rng, 5);
        if (!dict_results.empty()) {
            // 从结果中随机选择一个
            mutated_buffer = dict_results[rng() % dict_results.size()];
        } else {
            // 如果字典变异没有产生结果，则回退到通用变异
            mutated_buffer = current_buffer_vec;
            mutate_buffer_stdlib(mutated_buffer, rng); 
        }
    } else { // strategy == 2
        auto vars = extract_candidate_vars(current_buffer_vec);
        std::vector<std::vector<uint8_t>> queue_bufs = {current_buffer_vec}; 
        auto var_combine_results = http_queue_var_combine_stage(current_buffer_vec, vars, queue_bufs, rng);

        if (!var_combine_results.empty()) {
            // 从结果中随机选择一个
            mutated_buffer = var_combine_results[rng() % var_combine_results.size()];
        } else {
            // 如果变量组合变异没有产生结果，则回退到通用变异
            mutated_buffer = current_buffer_vec;
            mutate_buffer_stdlib(mutated_buffer, rng); 
        }
    }

    // 确保变异后的缓冲区大小不超过 MaxSize
    if (mutated_buffer.size() > MaxSize) {
        mutated_buffer.resize(MaxSize);
    }
    
    // 如果变异结果为空，或者由于 MaxSize 限制变得过小，可以考虑恢复到原始输入或一个很小的有效输入
    if (mutated_buffer.empty()) {
        if (Size > 0) {
            // 至少保持一个字节，避免返回空数据
            mutated_buffer.assign(Data, Data + std::min(Size, (size_t)1));
        } else {
            return 0; // 无法生成有效变异
        }
    }

    // 将变异后的数据拷贝回 LibFuzzer 提供的 Data 缓冲区
    memcpy(Data, mutated_buffer.data(), mutated_buffer.size());
    
    // 返回新的数据大小
    return mutated_buffer.size();
}

// 可选：LLVMFuzzerCustomCrossOver
// 如果你需要自定义交叉变异，可以实现这个函数。
// 否则，LibFuzzer 会使用其内置的交叉变异策略。
/*
extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
                                            const uint8_t *Data2, size_t Size2,
                                            uint8_t *Out, size_t MaxOutSize,
                                            unsigned int Seed) {
    // 这是一个示例实现，简单地选择其中一个输入或进行拼接。
    // 你可以在这里实现更智能的 HTTP 协议感知交叉变异。
    std::mt19937 rng(Seed);
    std::vector<uint8_t> result_buf;

    if (rng() % 2 == 0) { // Choose Data1
        result_buf.assign(Data1, Data1 + Size1);
    } else { // Choose Data2
        result_buf.assign(Data2, Data2 + Size2);
    }

    // Optional: Splice parts of Data1 and Data2
    // If you want more advanced crossover, you'd parse HttpTriplet from Data1 and Data2,
    // then combine their segments (e.g., header from one, body from another).

    if (result_buf.size() > MaxOutSize) {
        result_buf.resize(MaxOutSize);
    }

    memcpy(Out, result_buf.data(), result_buf.size());
    return result_buf.size();
}
*/
