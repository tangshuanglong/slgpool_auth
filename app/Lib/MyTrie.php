<?php

namespace App\Lib;

use Swoft\Bean\Annotation\Mapping\Bean;
use Swoft\Bean\Annotation\Mapping\Inject;
use Swoft\Bean\BeanFactory;

/**
 * 节点类
 * Class TrieNode
 * @package App\Lib
 */
class TrieNode{
    public $node;
    public $children = [];
    public $is_ending = false;

    public function __construct($node)
    {
        $this->node = $node;
    }
}

/**
 * 前缀树
 * Class MyTrie
 * @package App\Lib
 * @Bean("MyTrie")
 */
class MyTrie{

    /**
     * @Inject()
     * @var MyCommon
     */
    private $myCommon;

    private $trie_map;

    /**
     * MyTrie constructor.
     */
    public function __construct()
    {
        $this->trie_map = new TrieNode('/');
        $bad_lang_data = file(dirname(dirname(__DIR__)).'/public/bad_lang.txt');
        $this->init_data($bad_lang_data);
        unset($bad_lang_data);
    }

    /**
     * @param $node
     * @return array
     */
    public function TrieNode($node)
    {
        return [
            'node' => $node,
            'children' => [],
            'is_ending' => false,
        ];
    }

    /**
     * @return TrieNode
     */
    public function get_trie_map()
    {
        return $this->trie_map;
    }

    /**
     * 获取单个字符，字符集为uft-8
     * @param string $str
     * @param int $start
     * @return string
     */
    public function get_single_char(string $str, int $start): string
    {
        return mb_substr($str, $start, 1);
    }

    /**
     * 初始化数据，使用数组
     * @param array $data
     */
    public function init_data_array(array $data): void
    {
        $this->trie_map = $this->TrieNode('/');
        foreach ($data as $words) {
            $words = trim($words);
            $trie_map =& $this->trie_map;
            $len = mb_strlen($words);
            for ($i = 0; $i < $len; $i++) {
                $word = $this->get_single_char($words, $i);
                if (!isset($trie_map['children'][$word])) {
                    $new_node = $this->TrieNode($word);
                    $trie_map['children'][$word] = $new_node;
                }
                $trie_map =& $trie_map['children'][$word];
            }
            $trie_map['is_ending'] = true;
        }
    }

    /**
     * 初始化数据。使用对象，对象更优
     * @param array $data
     */
    public function init_data(array $data): void
    {
        $this->trie_map = new TrieNode('/');
        foreach ($data as $words) {
            $words = trim($words);
            $trie_map = $this->trie_map;
            $len = mb_strlen($words);
            for ($i = 0; $i < $len; $i++) {
                $word = $this->get_single_char($words, $i);
                if (!isset($trie_map->children[$word])) {
                    $new_node = new TrieNode($word);
                    $trie_map->children[$word] = $new_node;
                }
                $trie_map = $trie_map->children[$word];
            }
            $trie_map->is_ending = true;
        }
    }

    /**
     * 判断是否存在
     * @param $str
     * @return bool
     */
    public function exists_array($str)
    {
        $trie_map = $this->trie_map;
        $len = mb_strlen($str);
        for ($i = 0; $i < $len; $i++) {
            $word = $this->get_single_char($str, $i);
            if (!isset($trie_map['children'][$word])) {
                continue;
            }
            $trie_map = $trie_map['children'][$word];
        }
        if ($trie_map['is_ending'] === true) {
            return true;
        }
        return false;
    }

    /**
     * 判断是否存在
     * @param $str
     * @return bool
     */
    public function exists($str)
    {
        $trie_map = $this->trie_map;
        $len = mb_strlen($str);
        for ($i = 0; $i < $len; $i++) {
            $word = $this->get_single_char($str, $i);
            if (!isset($trie_map->children[$word])) {
                continue;
            }
            $trie_map = $trie_map->children[$word];
        }
        if ($trie_map->is_ending === true) {
            return true;
        }
        return false;
    }


}
